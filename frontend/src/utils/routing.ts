import { DetailKind, MainView, RouteState } from '../models/appTypes';

export function routeFromHash(hash: string): RouteState {
  const normalized = hash.replace(/^#\/?/, '').replace(/^\/+/, '');
  if (!normalized) return { view: 'incidents' };
  const [first, second, ...rest] = normalized.split('/');
  const view = first === 'operations' ? 'incidents' : first;
  const collection = second === 'incident' ? 'incidents' : second === 'alert' ? 'alerts' : second;
  if ((isMainView(view) || first === 'operations') && (collection === 'incidents' || collection === 'alerts')) {
    const id = rest.length > 0 ? decodeRoutePart(rest.join('/')) : '';
    if (collection === 'incidents' && id) {
      return { view: isMainView(view) ? view : 'incidents', detailKind: 'incident', detailID: id };
    }
    if (collection === 'alerts' && id) {
      return { view: isMainView(view) ? view : 'alerts', detailKind: 'alert', detailID: id };
    }
  }
  const rawKind = view;
  const id = second ? decodeRoutePart([second, ...rest].join('/')) : '';
  if ((rawKind === 'incidents' || rawKind === 'incident') && id) {
    return { view: 'incidents', detailKind: 'incident', detailID: id };
  }
  if ((rawKind === 'alerts' || rawKind === 'alert') && id) {
    return { view: 'alerts', detailKind: 'alert', detailID: id };
  }
  if (isMainView(rawKind)) {
    return { view: rawKind };
  }
  return { view: 'incidents' };
}

function decodeRoutePart(value: string) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function isMainView(value: string): value is MainView {
  return value === 'incidents' || value === 'archived' || value === 'trash' || value === 'alerts' || value === 'analysis';
}

export function hashForView(view: MainView) {
  return `#/${view}`;
}

export function hashForDetail(kind: DetailKind, id: string, view: MainView) {
  const collection = kind === 'incident' ? 'incidents' : 'alerts';
  return `#/${view}/${collection}/${encodeURIComponent(id)}`;
}
