import { formatDistanceToNow, parseISO } from "date-fns";
import { es } from "date-fns/locale";
import { Download, Eye, Hash, FileText } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  REPORT_KIND_LABELS,
  REPORT_KIND_TONES,
  type Report,
} from "@/lib/mocks/reports";
import { FRAMEWORK_CATALOG } from "@/lib/mocks/frameworks";

export function ReportCard({ report }: { report: Report }) {
  return (
    <Card className="group/report overflow-hidden transition-all hover:border-primary/40">
      {/* Thumbnail / preview */}
      <div className="relative aspect-[4/3] border-b border-border/60 bg-gradient-to-br from-card to-muted/20 p-6">
        <div className="flex h-full flex-col">
          <div className="mb-3 flex items-start justify-between">
            <FileText className="h-5 w-5 text-primary" />
            <Badge
              variant="outline"
              className={cn(
                "font-mono text-[10px] uppercase tracking-wider",
                REPORT_KIND_TONES[report.kind]
              )}
            >
              {REPORT_KIND_LABELS[report.kind]}
            </Badge>
          </div>

          <h3 className="line-clamp-2 text-sm font-semibold leading-snug">
            {report.title}
          </h3>

          {/* Simulated document lines */}
          <div className="mt-3 flex-1 space-y-1.5 opacity-50">
            <div className="h-1 w-full rounded-sm bg-muted-foreground/30" />
            <div className="h-1 w-[85%] rounded-sm bg-muted-foreground/30" />
            <div className="h-1 w-[70%] rounded-sm bg-muted-foreground/30" />
            <div className="h-1 w-[90%] rounded-sm bg-muted-foreground/30" />
            <div className="h-1 w-[60%] rounded-sm bg-muted-foreground/30" />
            <div className="h-1 w-[80%] rounded-sm bg-muted-foreground/30" />
          </div>

          <div className="mt-auto flex items-center gap-2 font-mono text-[10px] text-muted-foreground">
            <span>{report.pageCount} pág</span>
            <span>·</span>
            <span>{(report.sizeKb / 1024).toFixed(1)} MB</span>
            <span>·</span>
            <span className="uppercase">{report.format}</span>
          </div>
        </div>
      </div>

      <CardContent className="space-y-3 p-4">
        <div className="space-y-1 text-xs">
          <p className="text-muted-foreground">{report.scope}</p>
          <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
            <span>
              {formatDistanceToNow(parseISO(report.generatedAt), {
                addSuffix: true,
                locale: es,
              })}
            </span>
            <span>·</span>
            <span className="font-mono">por {report.generatedBy}</span>
          </div>
        </div>

        <div className="flex flex-wrap gap-1">
          {report.frameworks.slice(0, 4).map((id) => (
            <Badge
              key={id}
              variant="outline"
              className="font-mono text-[9px] text-muted-foreground"
            >
              {FRAMEWORK_CATALOG[id].shortName}
            </Badge>
          ))}
          {report.frameworks.length > 4 ? (
            <Badge
              variant="outline"
              className="font-mono text-[9px] text-muted-foreground"
            >
              +{report.frameworks.length - 4}
            </Badge>
          ) : null}
        </div>

        <div className="flex items-center justify-between border-t border-border/40 pt-3">
          <span className="inline-flex items-center gap-1 font-mono text-[9px] text-muted-foreground">
            <Hash className="h-2.5 w-2.5" />
            sha256:{report.hash}…
          </span>
          <div className="flex gap-1">
            <Button size="icon-sm" variant="ghost" aria-label="Ver">
              <Eye className="h-3.5 w-3.5" />
            </Button>
            <Button size="icon-sm" variant="ghost" aria-label="Descargar">
              <Download className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
