package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
)

// Временное имя файла в новом каталоге: под итоговым именем файл появляется
// только целиком
const moveSuffix = ".torsher-move"

// Подмена в тестах: `EXDEV` на любой ФС
var linkFile = linkMoveFile

// Чужой файл под итоговым именем в новом каталоге: перенос его не трогает
var errFileExists = errors.New("file already exists in the new directory")

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// Один каталог под разными путями: симлинк, bind-mount (тот же inode) или
// один сетевой экспорт, смонтированный дважды (inode разные — видно только
// по пробному файлу). Перенос в такой каталог удалил бы исходники вместе с
// «копией»
func sameDir(from, to string) bool {
	if samePath(from, to) {
		return true
	}

	source, err := os.OpenRoot(from)
	if err != nil {
		return false
	}
	defer source.Close()
	destination, err := os.OpenRoot(to)
	if err != nil {
		return false
	}
	defer destination.Close()
	fromStat, fromErr := source.Stat(".")
	toStat, toErr := destination.Stat(".")
	if fromErr != nil || toErr != nil {
		return false
	}

	if os.SameFile(fromStat, toStat) {
		return true
	}

	var random [8]byte
	_, _ = rand.Read(random[:])
	name := ".torsher-same-" + hex.EncodeToString(random[:])
	file, err := destination.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	_ = file.Close()
	defer destination.Remove(name)

	_, err = source.Lstat(name)

	return err == nil
}

// Каталог раздачи; раздача без своего — в каталоге по умолчанию
func (a *api) dirOf(hash metainfo.Hash) string {
	if dir, ok := a.dirs.Load(hash); ok {
		return dir.(string)
	}

	return a.downloads
}

func (a *api) dirOrDefault(dir string) string {
	if dir == "" {
		return a.downloads
	}

	return filepath.Clean(dir)
}

// В сессии каталог по умолчанию не пишется: раздача идёт за `--downloads`
func (a *api) sessionDir(dir string) string {
	if samePath(dir, a.downloads) {
		return ""
	}

	return filepath.Clean(dir)
}

// Хранилище каталога; у каталога по умолчанию — хранилище клиента (`nil`).
// Хранилища не закрываются: их закрытие закрыло бы общие отметки кусков
func (a *api) storageFor(dir string) storage.ClientImpl {
	if samePath(dir, a.downloads) {
		return nil
	}

	a.storesMu.Lock()
	defer a.storesMu.Unlock()

	key := filepath.Clean(dir)
	if found, ok := a.stores[key]; ok {
		return found
	}

	created := trackedStorage{ClientImplCloser: fileStorage(key, a.completion), lifecycle: a.lifecycle}
	a.stores[key] = created

	return created
}

// Добавляет раздачу в клиент с хранилищем её каталога
func (a *api) addIn(mi *metainfo.MetaInfo, dir string) (*torrent.Torrent, error) {
	return a.addWithPolicy(mi, dir, a.session.get(mi.HashInfoBytes()))
}

func (a *api) addWithPolicy(mi *metainfo.MetaInfo, dir string, policy savedTorrent) (*torrent.Torrent, error) {
	if a.maintenanceBlocked(mi.HashInfoBytes(), metadataPaths(mi, dir)) {
		return nil, errMaintenance
	}
	info, err := mi.UnmarshalInfo()
	if err != nil {
		return nil, err
	}
	policy.Private = policy.Private || privateInfo(&info)
	spec, err := torrent.TorrentSpecFromMetaInfoErr(mi)
	if err != nil {
		return nil, err
	}
	if len(a.session.get(mi.HashInfoBytes()).GuardedPaths) > 0 {
		if t, ok := a.client.Torrent(mi.HashInfoBytes()); ok && samePath(a.dirOf(mi.HashInfoBytes()), dir) {
			if guarded, ok := a.guarded.Load(mi.HashInfoBytes()); ok && guarded == t {
				if policy.Private || a.private.contains(t.InfoHash()) {
					t, _, err := a.addChecked(spec, mi, policy.Private)
					return t, err
				}
				return t, nil
			}
		}
		return nil, errors.New("guarded session requires maintenance recovery")
	}

	spec.Storage = a.storageFor(dir)
	if err := a.ownership.reserve(mi.HashInfoBytes(), dir, metadataPaths(mi, dir)); err != nil {
		return nil, err
	}
	if policy.paused() || policy.Private {
		spec.DisallowDataDownload = true
		spec.DisallowDataUpload = true
	}

	t, _, err := a.addChecked(spec, mi, policy.Private)
	if err != nil {
		return nil, err
	}

	if samePath(dir, a.downloads) {
		a.dirs.Delete(t.InfoHash())
	} else {
		a.dirs.Store(t.InfoHash(), filepath.Clean(dir))
	}

	return t, nil
}

type moveState struct {
	Dir string `json:"dir"`
	// `running`, `done` или `failed`
	State      string `json:"state"`
	BytesTotal int64  `json:"bytesTotal"`
	BytesDone  int64  `json:"bytesDone"`
	Error      string `json:"error,omitempty"`
	// Вид ошибки для сервера: `exists` — в новом каталоге чужой файл
	Kind string `json:"kind,omitempty"`
}

type moveJob struct {
	mu    sync.Mutex
	state moveState
}

func (j *moveJob) snapshot() moveState {
	j.mu.Lock()
	defer j.mu.Unlock()

	return j.state
}

func (j *moveJob) update(change func(*moveState)) {
	j.mu.Lock()
	defer j.mu.Unlock()

	change(&j.state)
}

func (a *api) isMoving(hash metainfo.Hash) bool {
	a.movesMu.Lock()
	defer a.movesMu.Unlock()

	job, ok := a.moves[hash]

	return ok && job.snapshot().State == "running"
}

func (a *api) forgetMove(hash metainfo.Hash) {
	a.movesMu.Lock()
	defer a.movesMu.Unlock()

	delete(a.moves, hash)
}

func writeMoving(w http.ResponseWriter) {
	writeError(w, http.StatusConflict, "torrent_moving", errors.New("torrent is being moved"))
}

// Переносит раздачу в другой каталог в фоне. Раздача на время переноса уходит
// из клиента: не качает, не раздаёт, поток не открыть. Ход — `GET …/move`
func (a *api) startMove(w http.ResponseWriter, r *http.Request) {
	var requested metainfo.Hash
	if err := requested.FromHexString(r.PathValue("hash")); err != nil {
		writeError(w, 400, "invalid_hash", err)
		return
	}
	unlock, acquired := a.ownership.tryOperation(requested)
	if !acquired {
		writeMoving(w)
		return
	}
	async := false
	defer func() {
		if !async {
			unlock()
		}
	}()
	t, ok := a.torrentOf(w, r)
	if !ok {
		return
	}

	hash := t.InfoHash()
	job := &moveJob{state: moveState{State: "running"}}

	// Задание занимается до любого ввода-вывода: параллельный запрос получает
	// `torrent_moving`, а не второй перенос тех же файлов
	a.movesMu.Lock()
	if current, ok := a.moves[hash]; ok && current.snapshot().State == "running" {
		a.movesMu.Unlock()
		writeMoving(w)
		return
	}
	a.moves[hash] = job
	a.movesMu.Unlock()

	reject := func(status int, kind string, err error) {
		a.forgetMove(hash)
		writeError(w, status, kind, err)
	}

	var body struct {
		Dir string `json:"dir"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil || !filepath.IsAbs(body.Dir) {
		reject(http.StatusBadRequest, "invalid_dir", errors.New("dir must be an absolute path"))
		return
	}

	metaForFence := t.Metainfo()
	if a.maintenanceBlocked(hash, metadataPaths(&metaForFence, body.Dir)) {
		reject(409, "maintenance_held", errMaintenance)
		return
	}
	// Раздача только из поиска метаданных: `.torrent` для повторного открытия нет
	if !a.session.has(hash) {
		reject(http.StatusNotFound, "torrent_not_found", errors.New("torrent is not in the engine"))
		return
	}

	if len(a.session.get(hash).GuardedPaths) > 0 {
		reject(409, "source_identity_guarded", errors.New("Files are protected after maintenance cancellation. To move them, remove the download while keeping files, then add it again after checking the source."))
		return
	}
	from := a.dirOf(hash)
	to := filepath.Clean(body.Dir)
	job.update(func(state *moveState) { state.Dir = to })
	if err := a.ownership.reserve(hash, to, metadataPaths(&metaForFence, to)); err != nil {
		reject(409, "storage_path_conflict", err)
		return
	}
	defer func() {
		if !async {
			dir := a.dirOf(hash)
			a.ownership.replace(hash, storageClaim{paths: metadataPaths(&metaForFence, dir), dir: dir})
		}
	}()

	if err := os.MkdirAll(to, 0o755); err != nil {
		reject(http.StatusInternalServerError, "storage", err)
		return
	}

	if samePath(from, to) {
		job.update(func(state *moveState) { state.State = "done" })
		writeJSON(w, http.StatusOK, job.snapshot())
		return
	}

	// `.torrent` из сессии, а не `t.Metainfo()`: собранный клиентом заново он
	// не открывается обратно (`no piece root set`)
	mi, err := metainfo.LoadFromFile(a.session.path(hash, ".torrent"))
	if err != nil {
		reject(http.StatusInternalServerError, "storage", err)
		return
	}

	info := t.Info()
	saved := a.session.get(hash)

	// Тот же каталог под другим путём: копировать нечего, а перенос удалил бы
	// исходники. Раздача только переоткрывается по новому пути, чтобы сессия и
	// сервер ссылались на один и тот же путь — иначе старый путь (снятый
	// симлинк, отмонтированный экспорт) остался бы в сессии навсегда
	if sameDir(from, to) {
		saved.Dir = a.sessionDir(to)
		saved.MovingTo = ""
		saved.MovedFrom = ""
		saved.Placed = nil
		if err := a.session.saveSelection(hash, saved); err != nil {
			reject(http.StatusInternalServerError, "storage", err)
			return
		}

		a.flushUploaded(t)
		a.dropPrivateTracker(t)
		complete := dropTorrent(t)
		a.windows.forget(hash)
		if !a.lifecycle.settled(hash) {
			reject(500, "storage", errors.New("torrent storage has not closed"))
			return
		}
		adoptPartFiles(to, info)

		// Сессия уже переключена: раздача вернётся при перезапуске движка
		if err := a.reopen(mi, to, saved, complete); err != nil {
			a.logger.With("infoHash", hash.HexString()).Error("reopen torrent", "err", err)
		}

		job.update(func(state *moveState) { state.State = "done" })
		writeJSON(w, http.StatusOK, job.snapshot())
		return
	}

	// Поставленное прошлой попыткой в другой каталог к этому не относится
	if !samePath(saved.MovingTo, to) {
		saved.Placed = nil
	}

	// Отметка до первого файла: перезапуск посреди переноса уберёт
	// недоделанное в новом каталоге (`finishMove`)
	saved.MovingTo = to
	if err := a.session.saveSelection(hash, saved); err != nil {
		reject(http.StatusInternalServerError, "storage", err)
		return
	}

	// Ожидание проверок кусков не держит ответ: задание уже занято
	async = true
	go func() {
		defer unlock()
		a.flushUploaded(t)
		a.dropPrivateTracker(t)
		complete := dropTorrent(t)
		if !a.lifecycle.settled(hash) {
			job.update(func(state *moveState) { state.State = "failed"; state.Error = "torrent storage has not closed" })
			return
		}
		a.windows.forget(hash)
		a.runMove(job, mi, info, from, to, saved, complete)
	}()

	writeJSON(w, http.StatusAccepted, job.snapshot())
}

// Сколько перенос ждёт, пока куски допроверятся перед тем, как раздачу убрать
const settleTimeout = 30 * time.Second

// Убирает раздачу из клиента и возвращает её скачанные куски. Сразу после
// закачки последние куски ещё проверяются по хэшу и записывают отметку:
// проверка, оборванная закрытием хранилища, снимает отметку, и такие куски
// качались бы снова. Поэтому сначала ждём, пока проверки закончатся, а
// открытая заново раздача перепроверяет то, что всё же потерялось (`reopen`)
func dropTorrent(t *torrent.Torrent) []int {
	deadline := time.Now().Add(settleTimeout)

	for time.Now().Before(deadline) && piecesBusy(t) {
		time.Sleep(20 * time.Millisecond)
	}

	var complete []int

	for index := range t.NumPieces() {
		if t.Piece(index).State().Complete {
			complete = append(complete, index)
		}
	}

	t.Drop()

	return complete
}

func piecesBusy(t *torrent.Torrent) bool {
	for index := range t.NumPieces() {
		state := t.Piece(index).State()
		if state.Hashing || state.QueuedForHash || state.Marking {
			return true
		}
	}

	return false
}

func (a *api) moveStatus(w http.ResponseWriter, r *http.Request) {
	var hash metainfo.Hash

	if err := hash.FromHexString(r.PathValue("hash")); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_hash", err)
		return
	}

	a.movesMu.Lock()
	job, ok := a.moves[hash]
	a.movesMu.Unlock()

	if !ok {
		writeError(w, http.StatusNotFound, "move_not_found", errors.New("torrent is not being moved"))
		return
	}

	writeJSON(w, http.StatusOK, job.snapshot())
}

// Три шага, после каждого состояние рабочее: файлы ставятся в новый каталог
// рядом с исходниками → раздача открывается в новом каталоге → исходники
// удаляются. Сбой первого шага убирает поставленное, раздача остаётся на месте
func (a *api) runMove(job *moveJob, mi *metainfo.MetaInfo, info *metainfo.Info, from, to string, saved savedTorrent, complete []int) {
	hash := mi.HashInfoBytes()
	defer func() {
		dir := a.dirOrDefault(a.session.get(hash).Dir)
		a.ownership.replace(hash, storageClaim{paths: metadataPaths(mi, dir), dir: dir})
	}()
	log := a.logger.With("infoHash", hash.HexString())
	log.Info("torrent move started")

	fail := func(err error) {
		removePlaced(info, to, saved.Placed)

		saved.MovingTo = ""
		saved.Placed = nil
		if err := a.session.saveSelection(hash, saved); err != nil {
			log.Warn("save session", "err", err)
		}

		if err := a.reopen(mi, from, saved, complete); err != nil {
			log.Warn("reopen torrent", "err", err)
		}

		job.update(func(state *moveState) {
			state.State = "failed"
			state.Error = err.Error()
			if errors.Is(err, errFileExists) {
				state.Kind = "exists"
			}
		})
		log.Warn("torrent move failed", "err", err)
	}

	total, err := dataBytes(info, from)
	if err != nil {
		fail(err)
		return
	}

	job.update(func(state *moveState) { state.BytesTotal = total })

	progress := func(n int64) {
		job.update(func(state *moveState) { state.BytesDone += n })
	}

	// Намерение пишется в сессию до того, как файл появится в новом каталоге:
	// откат и `finishMove` удаляют только записанное, чужой файл цел
	placed := placedFiles{
		owned: func(rel string) bool { return slices.Contains(saved.Placed, rel) },
		claim: func(rel string) error {
			saved.Placed = append(saved.Placed, rel)
			return a.session.saveSelection(hash, saved)
		},
	}

	if err := placeFiles(info, from, to, placed, progress); err != nil {
		fail(err)
		return
	}

	switched := saved
	switched.Dir = a.sessionDir(to)
	switched.MovingTo = ""
	switched.MovedFrom = from
	switched.Placed = nil

	if err := a.session.saveSelection(hash, switched); err != nil {
		fail(err)
		return
	}

	saved = switched

	// Файлы уже в новом каталоге и сессия переключена: задание удалось,
	// а раздача без клиента до перезапуска движка — повод для ошибки в журнале
	if err := a.reopen(mi, to, saved, complete); err != nil {
		log.Error("reopen torrent", "err", err)
	}

	if err := removeSources(info, from, to); err != nil {
		log.Warn("remove moved files", "err", err)
	}

	saved.MovedFrom = ""
	if err := a.session.saveSelection(hash, saved); err != nil {
		log.Warn("save session", "err", err)
	}

	job.update(func(state *moveState) { state.State = "done" })
	log.Info("torrent move finished", "bytes", total)
}

// Раздача снова в клиенте в своём каталоге, с выбором и паузой, как была.
// `complete` — куски, скачанные до того, как раздачу убрали из клиента
func (a *api) reopen(mi *metainfo.MetaInfo, dir string, saved savedTorrent, complete []int) error {
	t, err := a.addIn(mi, dir)
	if err != nil {
		return err
	}

	<-t.GotInfo()
	a.verifyHoles(t)

	var lost []torrent.Piece
	for _, index := range complete {
		if piece := t.Piece(index); !piece.State().Complete {
			lost = append(lost, piece)
		}
	}
	if len(lost) > 0 {
		a.verifyPieces(t, lost)
	}

	if saved.paused() {
		a.setPaused(t, true, saved.Selected)
		return nil
	}
	if saved.Private {
		a.setPaused(t, false, saved.Selected)
		a.sched.poke()
		return nil
	}

	return setFiles(t, saved.Selected, nil, saved.Low)
}

func movePaths(info *metainfo.Info) ([]string, error) {
	files := info.UpvertedFiles()
	paths := make([]string, 0, len(files))
	for i := range files {
		path := filePathOf(storage.FilePathMakerOpts{Info: info, File: &files[i]})
		if !isInside(".", path) {
			return nil, fmt.Errorf("file %q is outside the downloads directory", path)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func dataBytes(info *metainfo.Info, from string) (int64, error) {
	paths, err := movePaths(info)
	if err != nil {
		return 0, err
	}
	root, err := os.OpenRoot(from)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer root.Close()

	var total int64
	for _, path := range paths {
		total += dataSize(root, path)
	}
	return total, nil
}

func dataSize(root *os.Root, path string) int64 {
	item, err := root.Lstat(path)
	if err != nil || !item.Mode().IsRegular() {
		return 0
	}
	file, err := root.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !os.SameFile(item, info) {
		return 0
	}
	size := info.Size()
	holes, _ := fileHolesOf(file)
	for _, hole := range holes {
		size -= hole.end - hole.start
	}
	return size
}

type placedFiles struct {
	owned func(rel string) bool
	claim func(rel string) error
}

func placeFiles(info *metainfo.Info, from, to string, placed placedFiles, progress func(int64)) error {
	paths, err := movePaths(info)
	if err != nil {
		return err
	}
	source, err := os.OpenRoot(from)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenRoot(to)
	if err != nil {
		return err
	}
	defer destination.Close()

	for _, path := range paths {
		item, err := source.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !item.Mode().IsRegular() {
			continue
		}
		if err := placeFile(source, destination, path, item, placed, progress); err != nil {
			return err
		}
	}
	return nil
}

func placeFile(source, destination *os.Root, path string, item os.FileInfo, placed placedFiles, progress func(int64)) error {
	if err := destination.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	existing, err := destination.Lstat(path)
	switch {
	case err == nil:
		if os.SameFile(item, existing) {
			progress(dataSize(source, path))
			return nil
		}
		if !placed.owned(path) {
			return errFileExists
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	case !placed.owned(path):
		if err := placed.claim(path); err != nil {
			return err
		}
	}

	temp := path + moveSuffix
	_ = destination.Remove(temp)
	if err := linkFile(source, path, destination, temp); err == nil {
		linked, err := destination.Lstat(temp)
		if err != nil || !linked.Mode().IsRegular() || !os.SameFile(item, linked) {
			_ = destination.Remove(temp)
			return errors.New("move source changed before linking")
		}
		progress(dataSize(source, path))
	} else if err := copySparse(source, path, destination, temp, progress); err != nil {
		_ = destination.Remove(temp)
		return err
	}

	if err := destination.Rename(temp, path); err != nil {
		_ = destination.Remove(temp)
		return err
	}
	return nil
}

func copySparse(source *os.Root, src string, destination *os.Root, dst string, progress func(int64)) error {
	in, err := source.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("move source is not a regular file")
	}
	size := info.Size()
	holes, _ := fileHolesOf(in)
	out, err := destination.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()

	if err := copyExtents(in, out, size, holes, progress); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	copied, err := out.Stat()
	if err != nil {
		return err
	}
	if copied.Size() != size {
		return fmt.Errorf("copy size mismatch: %d of %d bytes", copied.Size(), size)
	}
	return out.Close()
}

func copyExtents(in, out *os.File, size int64, holes []extent, progress func(int64)) error {
	// Полный размер сразу: дыры остаются дырами, хвост без данных — тоже
	if err := out.Truncate(size); err != nil {
		return err
	}

	buf := make([]byte, 1<<20)
	offset := int64(0)

	copyRange := func(start, end int64) error {
		if end <= start {
			return nil
		}

		writer := &progressWriter{w: io.NewOffsetWriter(out, start), progress: progress}
		_, err := io.CopyBuffer(writer, io.NewSectionReader(in, start, end-start), buf)

		return err
	}

	for _, hole := range holes {
		if err := copyRange(offset, hole.start); err != nil {
			return err
		}
		offset = hole.end
	}

	return copyRange(offset, size)
}

type progressWriter struct {
	w        io.Writer
	progress func(int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.progress(int64(n))

	return n, err
}

// Убирает из нового каталога то, что поставила прерванная попытка: временные
// файлы и файлы из `placed`. Остальное под теми же именами — чужое
func removePlaced(info *metainfo.Info, to string, placed []string) {
	paths, err := movePaths(info)
	if err != nil {
		return
	}
	root, err := os.OpenRoot(to)
	if err != nil {
		return
	}
	defer root.Close()

	dirs := map[string]bool{}
	for _, path := range paths {
		_ = root.Remove(path + moveSuffix)
		if slices.Contains(placed, path) {
			if item, err := root.Lstat(path); err == nil && item.Mode().IsRegular() {
				_ = root.Remove(path)
			}
		}
		addParentDirs(dirs, ".", path)
	}

	_ = removeEmptyDirs(dirs, root.Remove)
}

// Удаляет исходники, у которых есть файл в новом каталоге, и опустевшие
// каталоги раздачи в старом
func removeSources(info *metainfo.Info, from, to string) error {
	paths, err := movePaths(info)
	if err != nil {
		return err
	}
	source, err := os.OpenRoot(from)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenRoot(to)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer destination.Close()

	var errs []error
	dirs := map[string]bool{}
	for _, path := range paths {
		src, srcErr := source.Lstat(path)
		dst, dstErr := destination.Lstat(path)
		if srcErr == nil && dstErr == nil && src.Mode().IsRegular() && dst.Mode().IsRegular() {
			if err := source.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		addParentDirs(dirs, ".", path)
	}

	errs = append(errs, removeEmptyDirs(dirs, source.Remove))
	return errors.Join(errs...)
}

// Доводит перенос, прерванный перезапуском: до переключения каталога
// поставленное в новом убирается, после — удаляются исходники в старом
func (a *api) finishMove(hash metainfo.Hash, info *metainfo.Info, dir string, saved *savedTorrent) {
	if saved.MovingTo == "" && saved.MovedFrom == "" {
		return
	}

	if saved.MovingTo != "" && !samePath(saved.MovingTo, dir) {
		removePlaced(info, saved.MovingTo, saved.Placed)
	}

	if saved.MovedFrom != "" && !samePath(saved.MovedFrom, dir) {
		if err := removeSources(info, saved.MovedFrom, dir); err != nil {
			a.logger.Warn("remove moved files", "infoHash", hash.HexString(), "err", err)
		}
	}

	saved.MovingTo = ""
	saved.MovedFrom = ""
	saved.Placed = nil

	if err := a.session.saveSelection(hash, *saved); err != nil {
		a.logger.Warn("save session", "infoHash", hash.HexString(), "err", err)
	}
}
