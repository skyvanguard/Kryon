"use client";

import { useMemo, useState } from "react";
import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  SortingState,
  useReactTable,
} from "@tanstack/react-table";
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Filter,
  Search,
  X,
  Zap,
} from "lucide-react";
import { format, parseISO } from "date-fns";
import { es } from "date-fns/locale";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBadge } from "./severity-badge";
import { FindingDetailSheet } from "./detail-sheet";
import {
  STATUS_LABELS,
  STATUS_TONES,
} from "@/lib/mocks/findings";
import { FRAMEWORK_CATALOG } from "@/lib/mocks/frameworks";
import { cn } from "@/lib/utils";
import type { Finding, FindingStatus, FrameworkId, Severity } from "@/lib/types";

interface Props {
  findings: readonly Finding[];
}

const SEVERITY_FILTERS: Array<{ value: "all" | Severity; label: string }> = [
  { value: "all", label: "Todas" },
  { value: "critical", label: "Crítica" },
  { value: "high", label: "Alta" },
  { value: "medium", label: "Media" },
  { value: "low", label: "Baja" },
  { value: "info", label: "Info" },
];

const STATUS_FILTERS: Array<{ value: "all" | FindingStatus; label: string }> = [
  { value: "all", label: "Todos" },
  { value: "open", label: "Abiertos" },
  { value: "triaging", label: "En triaje" },
  { value: "confirmed", label: "Confirmados" },
  { value: "remediating", label: "Remediando" },
  { value: "fixed", label: "Resueltos" },
  { value: "accepted", label: "Riesgo aceptado" },
  { value: "false_positive", label: "Falso positivo" },
];

export function FindingsTable({ findings }: Props) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [status, setStatus] = useState<"all" | FindingStatus>("all");
  const [framework, setFramework] = useState<"all" | FrameworkId>("all");
  const [sorting, setSorting] = useState<SortingState>([
    { id: "severity", desc: false },
  ]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (severity !== "all" && f.severity !== severity) return false;
      if (status !== "all" && f.status !== status) return false;
      if (framework !== "all" && !f.frameworks.includes(framework)) return false;
      if (needle) {
        const hay =
          `${f.title} ${f.cve ?? ""} ${f.assetName} ${f.id}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [findings, search, severity, status, framework]);

  const columns = useMemo<ColumnDef<Finding>[]>(
    () => [
      {
        accessorKey: "severity",
        header: ({ column }) => (
          <SortableHeader
            label="Sev"
            sorted={column.getIsSorted()}
            onClick={() => column.toggleSorting()}
          />
        ),
        sortingFn: (a, b) => {
          const order: Record<Severity, number> = {
            critical: 0,
            high: 1,
            medium: 2,
            low: 3,
            info: 4,
          };
          return order[a.original.severity] - order[b.original.severity];
        },
        cell: ({ row }) => (
          <div className="flex items-center gap-1.5">
            <SeverityBadge severity={row.original.severity} />
            {row.original.exploitable ? (
              <Zap
                className="h-3 w-3 text-[var(--critical)]"
                aria-label="Exploit disponible"
              />
            ) : null}
          </div>
        ),
        size: 120,
      },
      {
        accessorKey: "id",
        header: "ID",
        cell: ({ row }) => (
          <span className="font-mono text-[10px] text-muted-foreground">
            {row.original.id}
          </span>
        ),
        size: 90,
        enableSorting: false,
      },
      {
        accessorKey: "title",
        header: "Título",
        cell: ({ row }) => (
          <div className="max-w-md">
            <p className="truncate text-sm font-medium">{row.original.title}</p>
            {row.original.cve ? (
              <p className="font-mono text-[10px] text-muted-foreground">
                {row.original.cve}
              </p>
            ) : null}
          </div>
        ),
      },
      {
        accessorKey: "assetName",
        header: "Activo",
        cell: ({ row }) => (
          <span className="truncate font-mono text-xs text-muted-foreground">
            {row.original.assetName}
          </span>
        ),
      },
      {
        accessorKey: "cvss",
        header: ({ column }) => (
          <SortableHeader
            label="CVSS"
            sorted={column.getIsSorted()}
            onClick={() => column.toggleSorting()}
          />
        ),
        cell: ({ row }) =>
          row.original.cvss !== undefined ? (
            <span className="font-mono text-xs tabular-nums">
              {row.original.cvss.toFixed(1)}
            </span>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 80,
      },
      {
        accessorKey: "frameworks",
        header: "Frameworks",
        cell: ({ row }) => {
          const fws = row.original.frameworks;
          const visible = fws.slice(0, 2);
          const extra = fws.length - visible.length;
          return (
            <div className="flex flex-wrap gap-1">
              {visible.map((id) => (
                <Badge
                  key={id}
                  variant="outline"
                  className="font-mono text-[9px] text-muted-foreground"
                >
                  {FRAMEWORK_CATALOG[id].shortName}
                </Badge>
              ))}
              {extra > 0 ? (
                <Badge
                  variant="outline"
                  className="font-mono text-[9px] text-muted-foreground"
                >
                  +{extra}
                </Badge>
              ) : null}
            </div>
          );
        },
        enableSorting: false,
        size: 180,
      },
      {
        accessorKey: "status",
        header: "Estado",
        cell: ({ row }) => (
          <span
            className={cn(
              "inline-flex items-center rounded-md border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
              STATUS_TONES[row.original.status]
            )}
          >
            {STATUS_LABELS[row.original.status]}
          </span>
        ),
        size: 130,
      },
      {
        accessorKey: "ageDays",
        header: ({ column }) => (
          <SortableHeader
            label="Edad"
            sorted={column.getIsSorted()}
            onClick={() => column.toggleSorting()}
          />
        ),
        cell: ({ row }) => (
          <span
            className="text-xs text-muted-foreground"
            title={format(parseISO(row.original.detectedAt), "PPP", {
              locale: es,
            })}
          >
            {row.original.ageDays}d
          </span>
        ),
        size: 80,
      },
    ],
    []
  );

  const table = useReactTable({
    data: [...filtered],
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
  });

  const selectedFinding = useMemo(
    () => findings.find((f) => f.id === selectedId) ?? null,
    [findings, selectedId]
  );

  const openRow = (finding: Finding) => {
    setSelectedId(finding.id);
    setSheetOpen(true);
  };

  const clearFilters = () => {
    setSearch("");
    setSeverity("all");
    setStatus("all");
    setFramework("all");
  };

  const hasFilters =
    search !== "" ||
    severity !== "all" ||
    status !== "all" ||
    framework !== "all";

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar por título, CVE, asset o ID…"
            className="h-8 pl-8 text-xs"
          />
        </div>

        <Select
          value={severity}
          onValueChange={(v) => setSeverity(v as "all" | Severity)}
        >
          <SelectTrigger className="h-8 w-[140px] text-xs">
            <SelectValue placeholder="Severidad" />
          </SelectTrigger>
          <SelectContent>
            {SEVERITY_FILTERS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value} className="text-xs">
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select
          value={status}
          onValueChange={(v) => setStatus(v as "all" | FindingStatus)}
        >
          <SelectTrigger className="h-8 w-[150px] text-xs">
            <SelectValue placeholder="Estado" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_FILTERS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value} className="text-xs">
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select
          value={framework}
          onValueChange={(v) => setFramework(v as "all" | FrameworkId)}
        >
          <SelectTrigger className="h-8 w-[160px] text-xs">
            <SelectValue placeholder="Framework" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all" className="text-xs">
              Todos los frameworks
            </SelectItem>
            {(Object.keys(FRAMEWORK_CATALOG) as FrameworkId[]).map((id) => (
              <SelectItem key={id} value={id} className="text-xs">
                {FRAMEWORK_CATALOG[id].shortName}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {hasFilters ? (
          <Button size="sm" variant="ghost" onClick={clearFilters}>
            <X className="h-3.5 w-3.5" />
            Limpiar
          </Button>
        ) : null}

        <div className="ml-auto flex items-center gap-1.5 rounded-md border border-border/60 bg-card/40 px-2 py-1 font-mono text-[10px] text-muted-foreground">
          <Filter className="h-3 w-3" />
          {filtered.length} de {findings.length}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-lg border border-border/60">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow
                key={headerGroup.id}
                className="border-b border-border/60 bg-muted/30 hover:bg-muted/30"
              >
                {headerGroup.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    style={{ width: header.column.columnDef.size }}
                    className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground"
                  >
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext()
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  onClick={() => openRow(row.original)}
                  className="cursor-pointer border-b border-border/40 transition-colors hover:bg-muted/30"
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id} className="py-2">
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="h-32 text-center text-xs text-muted-foreground"
                >
                  No hay findings que coincidan con los filtros aplicados.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">
          Página {table.getState().pagination.pageIndex + 1} de{" "}
          {table.getPageCount()}
        </span>
        <div className="flex items-center gap-1">
          <Button
            size="icon-sm"
            variant="outline"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
            aria-label="Página anterior"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </Button>
          <Button
            size="icon-sm"
            variant="outline"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
            aria-label="Página siguiente"
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      <FindingDetailSheet
        finding={selectedFinding}
        open={sheetOpen}
        onOpenChange={setSheetOpen}
      />
    </div>
  );
}

function SortableHeader({
  label,
  sorted,
  onClick,
}: {
  label: string;
  sorted: false | "asc" | "desc";
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider transition-colors hover:text-foreground"
    >
      {label}
      <ArrowUpDown
        className={cn(
          "h-3 w-3 transition-colors",
          sorted ? "text-foreground" : "text-muted-foreground/50"
        )}
      />
    </button>
  );
}
