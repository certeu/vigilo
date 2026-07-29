import { useMemo, useState } from "react";
import {
  ChevronDownIcon,
  ChevronRightIcon,
  DocumentIcon,
  FolderIcon,
} from "@heroicons/react/24/outline";

// Browse-only directory tree, built from a flat list of file paths. Structure only —
// there is no way (and no backend endpoint) to open file contents.
interface Node {
  name: string;
  children: Map<string, Node>;
  isFile: boolean;
}

function buildTree(paths: string[]): Node {
  const root: Node = { name: "", children: new Map(), isFile: false };
  for (const p of paths) {
    const parts = p.split("/").filter(Boolean);
    let cur = root;
    parts.forEach((part, i) => {
      const isFile = i === parts.length - 1;
      let child = cur.children.get(part);
      if (!child) {
        child = { name: part, children: new Map(), isFile };
        cur.children.set(part, child);
      }
      cur = child;
    });
  }
  return root;
}

function sortedChildren(node: Node): Node[] {
  // folders first, then files, each alphabetical
  return [...node.children.values()].sort((a, b) =>
    a.isFile === b.isFile ? a.name.localeCompare(b.name) : a.isFile ? 1 : -1,
  );
}

function TreeNode({ node, depth }: { node: Node; depth: number }) {
  const [open, setOpen] = useState(depth < 1); // top level expanded by default
  const pad = { paddingLeft: `${depth * 14 + 4}px` };
  if (node.isFile) {
    return (
      <div className="flex items-center gap-1.5 py-0.5 text-sm" style={pad}>
        <DocumentIcon className="h-4 w-4 shrink-0 text-slate" />
        <span className="mono truncate text-ink">{node.name}</span>
      </div>
    );
  }
  const children = sortedChildren(node);
  return (
    <div>
      <button
        type="button"
        className="flex w-full items-center gap-1.5 py-0.5 text-left text-sm hover:text-accent"
        style={pad}
        onClick={() => setOpen((o) => !o)}
      >
        {open ? (
          <ChevronDownIcon className="h-3.5 w-3.5 shrink-0 text-slate" />
        ) : (
          <ChevronRightIcon className="h-3.5 w-3.5 shrink-0 text-slate" />
        )}
        <FolderIcon className="h-4 w-4 shrink-0 text-accent/70" />
        <span className="mono truncate font-medium text-ink">{node.name}</span>
      </button>
      {open && children.map((c) => <TreeNode key={c.name} node={c} depth={depth + 1} />)}
    </div>
  );
}

export function FileTree({ paths }: { paths: string[] }) {
  const root = useMemo(() => buildTree(paths), [paths]);
  const top = sortedChildren(root);
  if (top.length === 0) {
    return <div className="py-6 text-center text-sm text-slate">No files.</div>;
  }
  return (
    <div className="max-h-[440px] overflow-auto">
      {top.map((c) => <TreeNode key={c.name} node={c} depth={0} />)}
    </div>
  );
}
