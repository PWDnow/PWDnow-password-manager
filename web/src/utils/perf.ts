export class LoginPerfTracker {
  private static instance = new LoginPerfTracker();
  private measurements: Record<string, number> = {};

  static get() { return this.instance; }

  markStart(step: string) {
    performance.mark(`${step}-start`);
  }

  markEnd(step: string) {
    performance.mark(`${step}-end`);
    try {
      performance.measure(step, `${step}-start`, `${step}-end`);
      const entries = performance.getEntriesByName(step);
      if (entries.length > 0) {
        this.measurements[step] = entries[entries.length - 1].duration;
      }
    } catch (e) {
      console.warn(`[Perf] Failed to measure ${step}:`, e);
    }
  }

  log() {
    console.table(this.measurements);
  }

  reset() {
    this.measurements = {};
    performance.clearMarks();
    performance.clearMeasures();
  }
}
