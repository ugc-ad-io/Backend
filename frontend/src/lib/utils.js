import { clsx } from "clsx";
import { twMerge } from "tailwind-merge"

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}

// Multi-creator briefs: `selected_creators` lists every hired creator; the singular
// `selected_creator` is only the legacy/first pick and must not be used to ask
// "is this creator on the brief?".
export const hiredCreatorIds = (campaign = {}) =>
  campaign?.selected_creators?.length
    ? campaign.selected_creators
    : (campaign?.selected_creator ? [campaign.selected_creator] : []);

export const isHiredOn = (campaign, userId) => hiredCreatorIds(campaign).includes(userId);

export const creatorsWanted = (campaign = {}) => Math.max(1, Number(campaign?.creators_wanted) || 1);

// Still taking bids: live, with fewer creators hired than the brief asked for.
export const hasOpenCreatorSlots = (campaign = {}) =>
  campaign?.status === 'active' && hiredCreatorIds(campaign).length < creatorsWanted(campaign);
