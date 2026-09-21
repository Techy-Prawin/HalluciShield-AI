// jsdom does not reliably ship requestAnimationFrame; provide a tick-based shim.
if (typeof window !== 'undefined') {
  window.requestAnimationFrame =
    window.requestAnimationFrame ||
    ((cb: FrameRequestCallback) =>
      window.setTimeout(() => cb(performance.now()), 16) as unknown as number);
  window.cancelAnimationFrame =
    window.cancelAnimationFrame ||
    ((id: number) => window.clearTimeout(id));
}