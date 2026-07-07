import { PageInfo } from '../types';

export const DASHBOARD_PAGE_SIZE = 15;

export function pageRequest(pageIndex: number) {
  return {
    limit: DASHBOARD_PAGE_SIZE,
    offset: Math.max(0, pageIndex) * DASHBOARD_PAGE_SIZE,
  };
}

export function emptyPage(pageIndex = 0): PageInfo {
  return {
    total: 0,
    limit: DASHBOARD_PAGE_SIZE,
    offset: Math.max(0, pageIndex) * DASHBOARD_PAGE_SIZE,
    has_more: false,
  };
}
