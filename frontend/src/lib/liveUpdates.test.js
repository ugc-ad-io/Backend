import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { startLiveUpdates, useLiveEffect } from './liveUpdates';

jest.mock('axios', () => ({ get: jest.fn() }));
let stop, root, host;
beforeEach(() => {
  jest.useFakeTimers();
  localStorage.setItem('token', 'test');
  Object.defineProperty(document, 'hidden', { configurable: true, value: false });
  global.IS_REACT_ACT_ENVIRONMENT = true;
});
afterEach(() => {
  stop?.();
  if (root) act(() => root.unmount());
  host?.remove();
  jest.useRealTimers();
  jest.clearAllMocks();
});
test('change cursors refresh mounted data without remounting the page', async () => {
  const load = jest.fn(), cleanup = jest.fn();
  function Screen() { useLiveEffect(() => { load(); return cleanup; }, []); return <input defaultValue="draft" />; }
  host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => { root.render(<Screen />); });
  let version = 'one';
  axios.get.mockImplementation(async () => ({ data: { version } }));
  await act(async () => { stop = startLiveUpdates(); });
  await act(async () => { jest.advanceTimersByTime(15000); });
  expect(load).toHaveBeenCalledTimes(1);
  version = 'two';
  await act(async () => { jest.advanceTimersByTime(15000); });
  expect(load).toHaveBeenCalledTimes(2);
  expect(cleanup).toHaveBeenCalledTimes(1);
  expect(host.querySelector('input').value).toBe('draft');
  host.querySelector('input').focus();
  version = 'three';
  await act(async () => { jest.advanceTimersByTime(15000); });
  expect(load).toHaveBeenCalledTimes(2);
});
