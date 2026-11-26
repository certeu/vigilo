import { Skeleton, SkeletonCard } from "./ui";

/**
 * The app frame (top bar, sidebar, page area) with placeholders, shown while the session
 * loads so the layout does not jump when the real Shell appears.
 */
export function ShellSkeleton() {
  return (
    <div className="min-h-screen bg-canvas" role="status" aria-label="Loading">
      <header className="flex h-14 items-center justify-between border-b border-line bg-surface px-4 sm:px-6">
        <span className="font-display text-lg font-semibold tracking-tight">Vigilo</span>
        <Skeleton className="h-6 w-28" />
      </header>
      <div className="flex">
        <nav aria-hidden="true" className="hidden min-h-[calc(100vh-3.5rem)] w-56 shrink-0 space-y-3 border-r border-line bg-surface p-3 md:block">
          {Array.from({ length: 7 }, (_, i) => <Skeleton key={i} className="h-7 w-full" />)}
        </nav>
        <main className="min-w-0 flex-1 space-y-4 p-4 sm:p-8">
          <Skeleton className="h-4 w-48" />
          <Skeleton className="h-7 w-72" />
          <div className="grid gap-4 sm:grid-cols-2">
            <SkeletonCard />
            <SkeletonCard />
          </div>
          <span className="sr-only">Loading…</span>
        </main>
      </div>
    </div>
  );
}
