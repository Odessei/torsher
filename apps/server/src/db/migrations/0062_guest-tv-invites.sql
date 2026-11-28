CREATE TABLE `guest_invites` (
	`id` text PRIMARY KEY NOT NULL,
	`token_hash` text NOT NULL,
	`profile_id` text NOT NULL,
	`name` text NOT NULL,
	`browser_claimed` integer DEFAULT false NOT NULL,
	`tv_claimed` integer DEFAULT false NOT NULL,
	`expires_at` integer NOT NULL,
	FOREIGN KEY (`profile_id`) REFERENCES `profiles`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `guest_invites_token_hash_unique` ON `guest_invites` (`token_hash`);--> statement-breakpoint
ALTER TABLE `device_pairings` ADD `guest` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `device_pairings` ADD `guest_profile_id` text REFERENCES profiles(id) ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE `devices` ADD `guest_profile_id` text REFERENCES profiles(id) ON DELETE CASCADE;
