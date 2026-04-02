import { useLocation } from "wouter";
import { format } from "date-fns";
import { useListScans, useDeleteScan, useCreateScan, getListScansQueryKey, getGetStatsSummaryQueryKey, getGetRecentActivityQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Terminal, ShieldAlert, ShieldCheck, AlertTriangle, Shield, Trash2, RefreshCw, Loader2, Globe, Clock, Search } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { Input } from "@/components/ui/input";
import { useState } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

export function ScanHistory() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState("");

  const { data: scansData, isLoading } = useListScans();
  const deleteScan = useDeleteScan();
  const createScan = useCreateScan();

  const scans = scansData?.scans || [];
  
  const filteredScans = scans.filter(scan => 
    scan.url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDelete = (id: string) => {
    deleteScan.mutate({ id }, {
      onSuccess: () => {
        toast({
          title: "Scan Deleted",
          description: "Target analysis removed from records.",
        });
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetStatsSummaryQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetRecentActivityQueryKey() });
      },
      onError: (error) => {
        toast({
          title: "Deletion Failed",
          description: error.message || "Failed to remove scan record.",
          variant: "destructive"
        });
      }
    });
  };

  const handleRescan = (url: string) => {
    createScan.mutate({
      data: {
        url: url,
        options: {
          checkHeaders: true,
          checkCors: true,
          checkSqlInjection: true,
          checkXss: true,
          checkOpenRedirect: true,
          checkHttpMethods: true,
          checkRateLimit: false,
        }
      }
    }, {
      onSuccess: (scan) => {
        toast({
          title: "Re-scan Initiated",
          description: "Target locked. Re-analyzing vectors...",
        });
        setLocation(`/scan/${scan.id}`);
      }
    });
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="flex flex-col gap-2">
          <h2 className="text-3xl font-mono font-bold tracking-tight text-primary">Scan History</h2>
          <p className="text-muted-foreground font-mono text-sm">Archived intelligence on target systems.</p>
        </div>
        <div className="relative w-full md:w-64">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input 
            placeholder="Search targets..." 
            className="pl-9 font-mono bg-background/50 border-border"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <Card className="bg-card/50 border-border/50">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border/50 text-xs font-mono text-muted-foreground uppercase bg-muted/20">
                  <th className="p-4 font-medium">Target</th>
                  <th className="p-4 font-medium">Date</th>
                  <th className="p-4 font-medium">Status</th>
                  <th className="p-4 font-medium">Risk Score</th>
                  <th className="p-4 font-medium">Findings</th>
                  <th className="p-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="font-mono text-sm">
                {isLoading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i} className="border-b border-border/20">
                      <td className="p-4"><Skeleton className="h-4 w-48" /></td>
                      <td className="p-4"><Skeleton className="h-4 w-32" /></td>
                      <td className="p-4"><Skeleton className="h-6 w-20 rounded-full" /></td>
                      <td className="p-4"><Skeleton className="h-4 w-12" /></td>
                      <td className="p-4"><Skeleton className="h-4 w-24" /></td>
                      <td className="p-4 text-right"><Skeleton className="h-8 w-20 inline-block" /></td>
                    </tr>
                  ))
                ) : filteredScans.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-muted-foreground">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <Terminal className="h-8 w-8 text-muted-foreground/50" />
                        <p>No scans found in database.</p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredScans.map((scan) => (
                    <tr key={scan.id} className="border-b border-border/20 hover:bg-muted/10 transition-colors group">
                      <td className="p-4">
                        <div 
                          className="flex items-center gap-2 font-medium cursor-pointer hover:text-primary transition-colors"
                          onClick={() => setLocation(`/scan/${scan.id}`)}
                        >
                          <Globe className="h-4 w-4 text-muted-foreground" />
                          <span className="truncate max-w-[200px] block">{scan.url}</span>
                        </div>
                      </td>
                      <td className="p-4 text-muted-foreground">
                        <div className="flex items-center gap-2">
                          <Clock className="h-3 w-3" />
                          {format(new Date(scan.createdAt), "MMM d, yyyy HH:mm")}
                        </div>
                      </td>
                      <td className="p-4">
                        <Badge variant="outline" className={`font-mono text-[10px] ${
                          scan.status === 'completed' ? 'border-primary text-primary' : 
                          scan.status === 'failed' ? 'border-destructive text-destructive' : 
                          'border-amber-500 text-amber-500 animate-pulse'
                        }`}>
                          {scan.status.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="p-4">
                        {scan.status === 'completed' ? (
                          <div className="flex items-center gap-2">
                            <span className={`font-bold ${
                              scan.riskLevel === 'critical' ? 'text-destructive' :
                              scan.riskLevel === 'high' ? 'text-orange-500' :
                              scan.riskLevel === 'medium' ? 'text-amber-500' :
                              scan.riskLevel === 'low' ? 'text-blue-500' :
                              'text-gray-500'
                            }`}>
                              {scan.riskScore !== null ? scan.riskScore : 'N/A'}
                            </span>
                            <span className="text-xs text-muted-foreground">/ 100</span>
                          </div>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>
                      <td className="p-4">
                        {scan.status === 'completed' ? (
                          <div className="flex items-center gap-1.5 text-xs">
                            {scan.criticalCount > 0 && <span className="text-destructive flex items-center gap-0.5"><ShieldAlert className="h-3 w-3"/> {scan.criticalCount}</span>}
                            {scan.highCount > 0 && <span className="text-orange-500 flex items-center gap-0.5"><ShieldAlert className="h-3 w-3"/> {scan.highCount}</span>}
                            {scan.mediumCount > 0 && <span className="text-amber-500 flex items-center gap-0.5"><AlertTriangle className="h-3 w-3"/> {scan.mediumCount}</span>}
                            {scan.lowCount > 0 && <span className="text-blue-500 flex items-center gap-0.5"><Shield className="h-3 w-3"/> {scan.lowCount}</span>}
                            {scan.vulnerabilityCount === 0 && <span className="text-primary flex items-center gap-0.5"><ShieldCheck className="h-3 w-3"/> Secure</span>}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>
                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                          <Button 
                            variant="ghost" 
                            size="icon" 
                            className="h-8 w-8 hover:text-primary hover:bg-primary/10"
                            onClick={() => handleRescan(scan.url)}
                            disabled={createScan.isPending}
                            title="Re-scan target"
                          >
                            <RefreshCw className={`h-4 w-4 ${createScan.isPending ? 'animate-spin' : ''}`} />
                          </Button>
                          
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button 
                                variant="ghost" 
                                size="icon" 
                                className="h-8 w-8 hover:text-destructive hover:bg-destructive/10"
                                title="Delete record"
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent className="border-destructive/20 bg-card">
                              <AlertDialogHeader>
                                <AlertDialogTitle className="font-mono flex items-center gap-2">
                                  <AlertTriangle className="h-5 w-5 text-destructive" />
                                  Confirm Purge
                                </AlertDialogTitle>
                                <AlertDialogDescription className="font-mono text-sm">
                                  Are you sure you want to permanently delete the analysis record for <span className="text-foreground font-bold">{scan.url}</span>? This action cannot be undone.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel className="font-mono">Cancel</AlertDialogCancel>
                                <AlertDialogAction 
                                  onClick={() => handleDelete(scan.id)}
                                  className="font-mono bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                >
                                  Purge Data
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
