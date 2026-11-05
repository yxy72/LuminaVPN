import type { Environment } from "../../../protocol/types";

type Handlers = {
  started(): void;
  succeeded(result: Environment): void;
  failed(error: unknown): void;
  finished(): void;
};

// A directory dialog can outlive an earlier check. Both opening and closing
// that selection invalidate checks, including their error and loading state.
export class EnvironmentChecks {
  private generation = 0;
  private selectingProfile = false;

  beginProfileSelection(): boolean {
    if (this.selectingProfile) return false;
    this.generation++;
    this.selectingProfile = true;
    return true;
  }

  endProfileSelection(): void {
    this.generation++;
    this.selectingProfile = false;
  }

  async run(read: () => Promise<Environment>, handlers: Handlers): Promise<void> {
    if (this.selectingProfile) return;
    const generation = ++this.generation;
    const current = () =>
      !this.selectingProfile && this.generation === generation;
    handlers.started();
    try {
      const result = await read();
      if (current()) handlers.succeeded(result);
    } catch (error) {
      if (current()) handlers.failed(error);
    } finally {
      if (current()) handlers.finished();
    }
  }
}
