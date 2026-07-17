import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/Tabs'
import { ExportPanel } from '@/components/utility/ExportPanel'
import { ImportPanel } from '@/components/utility/ImportPanel'
import { ChangeMasterPasswordPanel } from '@/components/utility/ChangeMasterPasswordPanel'

export function UtilityPage() {
  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold">Utility Database</h1>
      <Tabs defaultValue="export">
        <TabsList>
          <TabsTrigger value="export">Esporta</TabsTrigger>
          <TabsTrigger value="import">Importa</TabsTrigger>
          <TabsTrigger value="master">Cambia Master Password</TabsTrigger>
        </TabsList>
        <TabsContent value="export">
          <ExportPanel />
        </TabsContent>
        <TabsContent value="import">
          <ImportPanel />
        </TabsContent>
        <TabsContent value="master">
          <ChangeMasterPasswordPanel />
        </TabsContent>
      </Tabs>
    </div>
  )
}
