import { CheckCircle2, Settings as SettingsIcon } from "lucide-react";
import { PageHeader } from "@/components/app/page-header";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

export const metadata = { title: "Ajustes" };

export default function SettingsPage() {
  return (
    <div>
      <PageHeader
        title="Ajustes"
        description="Configuración de plataforma, usuarios, integraciones y API keys."
      />

      <div className="px-6 py-6">
        <Tabs defaultValue="general" className="space-y-5">
          <TabsList>
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="users">Usuarios</TabsTrigger>
            <TabsTrigger value="integrations">Integraciones</TabsTrigger>
            <TabsTrigger value="api">API Keys</TabsTrigger>
          </TabsList>

          <TabsContent value="general" className="space-y-5">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Organización</CardTitle>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <Field
                  label="Nombre de la organización"
                  defaultValue="BritImp Importadora S.A."
                />
                <Field
                  label="RUC"
                  defaultValue="80000123-4"
                  mono
                />
                <Field
                  label="Zona horaria"
                  defaultValue="America/Asuncion (GMT-3)"
                />
                <Field label="Idioma" defaultValue="Español (Paraguay)" />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Motor Kryon</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <InfoRow
                  label="Modelo activo"
                  value="kryon-14b (Qwen3-14B · 32K ctx)"
                  mono
                  ok
                />
                <InfoRow
                  label="Backend LLM"
                  value="Ollama local · 192.168.10.5:11434"
                  mono
                  ok
                />
                <InfoRow
                  label="Skills cargadas"
                  value="67 / 67 (core 11 · imported 28 · banking 8 · custom 20)"
                  ok
                />
                <InfoRow
                  label="Base de conocimiento"
                  value="ChromaDB · 287.432 vectores indexados"
                  mono
                  ok
                />
                <InfoRow
                  label="Force tool turns"
                  value="8 por turno de usuario"
                  mono
                  ok
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Retención y privacidad</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Field label="Retención de logs de escaneo" defaultValue="365 días" />
                <Field
                  label="Retención de findings cerrados"
                  defaultValue="730 días (requerido SOC 2)"
                />
                <Field
                  label="Retención de reportes"
                  defaultValue="1825 días (5 años, requerido BCP)"
                />
                <Separator />
                <p className="flex items-start gap-2 text-xs text-muted-foreground">
                  <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--success)]" />
                  <span>
                    Todos los datos procesados se mantienen dentro de tu
                    infraestructura. Kryon no envía datos a servicios externos.
                  </span>
                </p>
              </CardContent>
            </Card>

            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm">
                Descartar
              </Button>
              <Button size="sm">Guardar cambios</Button>
            </div>
          </TabsContent>

          <TabsContent value="users">
            <ComingSoon area="Usuarios" />
          </TabsContent>

          <TabsContent value="integrations">
            <ComingSoon area="Integraciones" />
          </TabsContent>

          <TabsContent value="api">
            <ComingSoon area="API Keys" />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

function Field({
  label,
  defaultValue,
  mono,
}: {
  label: string;
  defaultValue: string;
  mono?: boolean;
}) {
  return (
    <div className="space-y-1.5">
      <Label className="text-xs">{label}</Label>
      <Input
        defaultValue={defaultValue}
        className={mono ? "font-mono" : ""}
      />
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono,
  ok,
}: {
  label: string;
  value: string;
  mono?: boolean;
  ok?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <div className="flex items-center gap-2">
        {ok ? (
          <CheckCircle2 className="h-3.5 w-3.5 text-[var(--success)]" />
        ) : null}
        <span className={mono ? "font-mono" : ""}>{value}</span>
      </div>
    </div>
  );
}

function ComingSoon({ area }: { area: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16 text-center">
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full border border-border/60 bg-muted/40 text-muted-foreground">
          <SettingsIcon className="h-5 w-5" />
        </div>
        <h3 className="text-sm font-semibold">{area}</h3>
        <p className="mt-1 max-w-sm text-xs text-muted-foreground">
          Esta sección quedó fuera del alcance MVP y se habilita en la versión
          post-venta junto con el backend real.
        </p>
        <Badge variant="outline" className="mt-4 font-mono text-[10px]">
          próximamente
        </Badge>
      </CardContent>
    </Card>
  );
}
