import { useParams, Link } from "wouter";
import { useEffect, useState } from "react";
import { 
  useGetScan, 
  useGetScanStatus, 
  useGetScanEvents, 
  useGetScanVulnerabilities,
  getGetScanStatusQueryKey
} from "@workspace/api-client-react";
import { Terminal, ShieldAlert, ShieldCheck, AlertTriangle, Shield, Globe, Clock, ChevronDown, CheckCircle2, XCircle, Loader2, Info, Bug, Activity } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";
import { RiskGauge } from "@/components/risk-gauge";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

export function ScanDetail() {
  const params = useParams();
  const id = params.id as string;

  // Initial load
  const { data: scanData, isLoading: isLoadingScan } = useGetScan(id);
  
  // Status polling
  const isPolling = scanData?.scan?.status === 'running' || scanData?.scan?.status === 'pending';
  
  const { data: statusData } = useGetScanStatus(id, {
    query: {
      refetchInterval: isPolling ? 2000 : false,
      enabled: !!id,
    }
  });

  const { data: eventsData, isLoading: isLoadingEvents } = useGetScanEvents(id, {
    query: {
      refetchInterval: isPolling ? 2000 : false,
      enabled: !!id,
    }
  });

  const { data: vulnsData, isLoading: isLoadingVulns } = useGetScanVulnerabilities(id, {
    query: {
      refetchInterval: isPolling ? 2000 : false,
      enabled: !!id,
    }
  });

  const scan = scanData?.scan;
  const status = statusData || scanData?.scan; // fallback to scanData if status polling hasn't hit yet
  const events = eventsData?.events || [];
  const vulnerabilities = vulnsData?.vulnerabilities || [];

  if (isLoadingScan) {
    return (
      <div className="space-y-6 max-w-6xl mx-auto">
        <Skeleton className="h-12 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Skeleton className="h-48 col-span-2" />
          <Skeleton className="h-48" />
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] text-center">
        <AlertTriangle className="h-12 w-12 text-destructive mb-4" />
        <h2 className="text-2xl font-mono font-bold">Scan Not Found</h2>
        <p className="text-muted-foreground font-mono mt-2 mb-6">The requested analysis record does not exist or was purged.</p>
        <Link href="/scans">
          <a className="bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md font-mono text-sm">
            Return to History
          </a>
        </Link>
      </div>
    );
  }

  const isRunning = scan.status === 'running' || scan.status === 'pending';

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 border-b border-border/50 pb-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h2 className="text-2xl md:text-3xl font-mono font-bold tracking-tight break-all">
              {scan.url}
            </h2>
            <Badge variant="outline" className={`font-mono text-xs uppercase ${
              scan.status === 'completed' ? 'border-primary text-primary' : 
              scan.status === 'failed' ? 'border-destructive text-destructive' : 
              'border-amber-500 text-amber-500 animate-pulse'
            }`}>
              {scan.status}
            </Badge>
          </div>
          <div className="flex items-center gap-4 text-sm font-mono text-muted-foreground">
            <span className="flex items-center gap-1.5"><Globe className="h-4 w-4" /> Target Node</span>
            <span className="flex items-center gap-1.5"><Clock className="h-4 w-4" /> Initialized: {format(new Date(scan.createdAt), "MMM d, HH:mm:ss")}</span>
          </div>
        </div>
      </div>

      {/* Progress & Live Status */}
      {isRunning && statusData && 'progress' in statusData && (
        <Card className="border-primary/30 bg-primary/5">
          <CardContent className="p-6">
            <div className="flex justify-between items-center mb-3">
              <div className="flex items-center gap-2">
                <Loader2 className="h-5 w-5 text-primary animate-spin" />
                <span className="font-mono text-primary font-bold">ANALYSIS IN PROGRESS</span>
              </div>
              <span className="font-mono text-sm text-primary">{Math.round(statusData.progress)}%</span>
            </div>
            <Progress value={statusData.progress} className="h-2 bg-primary/20" indicatorColor="bg-primary" />
            <div className="mt-3 flex items-center justify-between text-xs font-mono text-muted-foreground">
              <span>Current Phase: <span className="text-foreground">{statusData.currentStage || "Initializing..."}</span></span>
              <span>Modules: {statusData.stagesCompleted?.length || 0} / {statusData.stagesTotal || 1}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="bg-card/50 col-span-1 md:col-span-2 flex flex-col justify-center">
          <CardContent className="p-6 flex flex-col md:flex-row items-center gap-8 h-full">
            <div className="flex-shrink-0">
              <RiskGauge score={scan.riskScore || 0} level={scan.riskLevel} size={140} />
            </div>
            <div className="flex-1 grid grid-cols-2 gap-4 w-full">
              <div className="space-y-1">
                <span className="text-xs font-mono text-muted-foreground uppercase flex items-center gap-1.5">
                  <ShieldAlert className="h-3 w-3 text-destructive" /> Critical
                </span>
                <p className="text-2xl font-mono text-destructive">{scan.criticalCount}</p>
              </div>
              <div className="space-y-1">
                <span className="text-xs font-mono text-muted-foreground uppercase flex items-center gap-1.5">
                  <ShieldAlert className="h-3 w-3 text-orange-500" /> High
                </span>
                <p className="text-2xl font-mono text-orange-500">{scan.highCount}</p>
              </div>
              <div className="space-y-1">
                <span className="text-xs font-mono text-muted-foreground uppercase flex items-center gap-1.5">
                  <AlertTriangle className="h-3 w-3 text-amber-500" /> Medium
                </span>
                <p className="text-2xl font-mono text-amber-500">{scan.mediumCount}</p>
              </div>
              <div className="space-y-1">
                <span className="text-xs font-mono text-muted-foreground uppercase flex items-center gap-1.5">
                  <Shield className="h-3 w-3 text-blue-500" /> Low
                </span>
                <p className="text-2xl font-mono text-blue-500">{scan.lowCount}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* System Info */}
        <Card className="bg-card/50">
          <CardHeader className="pb-3">
            <CardTitle className="font-mono text-sm flex items-center gap-2 text-muted-foreground">
              <Terminal className="h-4 w-4" /> Node Info
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="text-xs font-mono text-muted-foreground mb-1">Target Endpoint</div>
              <div className="font-mono text-sm bg-background p-2 rounded border border-border truncate" title={scan.url}>{scan.url}</div>
            </div>
            <div>
              <div className="text-xs font-mono text-muted-foreground mb-1">UUID</div>
              <div className="font-mono text-xs text-muted-foreground bg-background p-2 rounded border border-border break-all">{scan.id}</div>
            </div>
            <div>
              <div className="text-xs font-mono text-muted-foreground mb-1">Completion Time</div>
              <div className="font-mono text-sm">
                {scan.completedAt ? format(new Date(scan.completedAt), "MMM d, yyyy HH:mm:ss") : "Pending..."}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerabilities List */}
        <div className="space-y-4">
          <h3 className="text-xl font-mono font-bold flex items-center gap-2">
            <Bug className="h-5 w-5 text-primary" />
            Detected Vulnerabilities
          </h3>
          
          {isLoadingVulns ? (
             <div className="space-y-3">
               <Skeleton className="h-32 w-full" />
               <Skeleton className="h-32 w-full" />
             </div>
          ) : vulnerabilities.length === 0 ? (
            <Card className="border-dashed bg-background/50">
              <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                {isRunning ? (
                  <>
                    <Loader2 className="h-8 w-8 animate-spin mb-3 text-primary/50" />
                    <p className="font-mono text-sm">Scanning for vulnerabilities...</p>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-12 w-12 text-primary/50 mb-3" />
                    <p className="font-mono text-sm">No vulnerabilities detected. Target is secure.</p>
                  </>
                )}
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {vulnerabilities.map((vuln) => (
                <Card key={vuln.id} className={`border-l-4 ${
                  vuln.severity === 'critical' ? 'border-l-destructive bg-destructive/5' :
                  vuln.severity === 'high' ? 'border-l-orange-500 bg-orange-500/5' :
                  vuln.severity === 'medium' ? 'border-l-amber-500 bg-amber-500/5' :
                  vuln.severity === 'low' ? 'border-l-blue-500 bg-blue-500/5' :
                  'border-l-gray-500 bg-gray-500/5'
                }`}>
                  <CardHeader className="pb-2">
                    <div className="flex justify-between items-start">
                      <CardTitle className="font-mono text-lg">{vuln.title}</CardTitle>
                      <Badge variant="outline" className={`font-mono text-xs ml-2 flex-shrink-0 ${
                        vuln.severity === 'critical' ? 'border-destructive text-destructive bg-destructive/10' :
                        vuln.severity === 'high' ? 'border-orange-500 text-orange-500 bg-orange-500/10' :
                        vuln.severity === 'medium' ? 'border-amber-500 text-amber-500 bg-amber-500/10' :
                        vuln.severity === 'low' ? 'border-blue-500 text-blue-500 bg-blue-500/10' :
                        'border-gray-500 text-gray-500 bg-gray-500/10'
                      }`}>
                        {vuln.severity.toUpperCase()}
                        {vuln.cvssScore && ` (${vuln.cvssScore})`}
                      </Badge>
                    </div>
                    <CardDescription className="font-mono text-xs text-foreground/80 mt-1">
                      Path: <code className="bg-background px-1 py-0.5 rounded text-primary">{vuln.affectedEndpoint}</code>
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-sm font-sans text-muted-foreground">{vuln.description}</p>
                    
                    <Accordion type="single" collapsible className="w-full">
                      <AccordionItem value="payload" className="border-border/50">
                        <AccordionTrigger className="font-mono text-xs py-2 text-muted-foreground hover:text-foreground">
                          <span className="flex items-center gap-2"><Terminal className="h-3 w-3"/> Show Exploit Payload</span>
                        </AccordionTrigger>
                        <AccordionContent>
                          <div className="bg-background rounded border border-border p-3 font-mono text-xs overflow-x-auto text-orange-400">
                            {vuln.payload || "No payload logged."}
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      <AccordionItem value="remediation" className="border-border/50 border-b-0">
                        <AccordionTrigger className="font-mono text-xs py-2 text-muted-foreground hover:text-foreground">
                          <span className="flex items-center gap-2"><ShieldCheck className="h-3 w-3 text-primary"/> Remediation Guide</span>
                        </AccordionTrigger>
                        <AccordionContent>
                          <div className="bg-primary/5 rounded border border-primary/20 p-3 font-mono text-xs text-foreground/90">
                            {vuln.remediation}
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    </Accordion>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>

        {/* Attack Timeline / Events */}
        <div className="space-y-4">
          <h3 className="text-xl font-mono font-bold flex items-center gap-2">
            <Activity className="h-5 w-5 text-primary" />
            Attack Timeline
          </h3>
          
          <Card className="bg-card/50 border-border/50 overflow-hidden h-[800px] flex flex-col">
            <CardContent className="p-0 overflow-y-auto flex-1 custom-scrollbar">
              {isLoadingEvents ? (
                <div className="p-6 space-y-4">
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                </div>
              ) : events.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Terminal className="h-8 w-8 mb-3 text-muted-foreground/50" />
                  <p className="font-mono text-sm">No events recorded yet.</p>
                </div>
              ) : (
                <div className="relative p-6 font-mono text-xs">
                  {/* Vertical timeline line */}
                  <div className="absolute left-[35px] top-6 bottom-6 w-px bg-border"></div>
                  
                  <div className="space-y-6">
                    {events.map((event, i) => {
                      const isError = event.eventType === 'error';
                      const isFinding = event.eventType === 'finding';
                      const isReqRes = event.eventType === 'request' || event.eventType === 'response';
                      
                      let Icon = Info;
                      let iconColor = "text-blue-500 bg-blue-500/10";
                      
                      if (isError) {
                        Icon = XCircle;
                        iconColor = "text-destructive bg-destructive/10";
                      } else if (isFinding) {
                        Icon = Bug;
                        iconColor = "text-orange-500 bg-orange-500/10";
                      } else if (event.eventType === 'request') {
                        Icon = Globe;
                        iconColor = "text-emerald-500 bg-emerald-500/10";
                      } else if (event.eventType === 'response') {
                        Icon = Terminal;
                        iconColor = "text-purple-500 bg-purple-500/10";
                      }

                      return (
                        <div key={event.id} className="relative pl-10">
                          {/* Timeline dot */}
                          <div className={`absolute left-0 top-1.5 h-6 w-6 rounded-full border border-background flex items-center justify-center ${iconColor} z-10`}>
                            <Icon className="h-3 w-3" />
                          </div>
                          
                          <div className="bg-background border border-border/50 rounded-md overflow-hidden hover:border-border transition-colors">
                            <div className="flex justify-between items-start p-3 border-b border-border/30 bg-muted/10">
                              <div>
                                <span className={`font-bold mr-2 ${isError ? 'text-destructive' : isFinding ? 'text-orange-500' : 'text-primary'}`}>
                                  [{event.stage}]
                                </span>
                                <span className="text-foreground">{event.title}</span>
                              </div>
                              <span className="text-muted-foreground whitespace-nowrap ml-4">
                                {format(new Date(event.timestamp), "HH:mm:ss.SSS")}
                              </span>
                            </div>
                            
                            <div className="p-3">
                              <p className="text-muted-foreground mb-2">{event.description}</p>
                              
                              {isReqRes && (
                                <Accordion type="single" collapsible className="w-full mt-2">
                                  <AccordionItem value="details" className="border-none">
                                    <AccordionTrigger className="py-1 text-[10px] text-muted-foreground hover:text-foreground">
                                      View Raw Traffic
                                    </AccordionTrigger>
                                    <AccordionContent className="pt-2 pb-0">
                                      {event.eventType === 'request' && event.requestHeaders && (
                                        <div className="mb-2">
                                          <div className="text-[10px] text-muted-foreground mb-1 uppercase">Headers</div>
                                          <pre className="bg-black p-2 rounded text-green-400 overflow-x-auto border border-white/10">
                                            {event.requestHeaders}
                                          </pre>
                                        </div>
                                      )}
                                      {event.eventType === 'request' && event.payload && (
                                        <div>
                                          <div className="text-[10px] text-muted-foreground mb-1 uppercase">Payload</div>
                                          <pre className="bg-black p-2 rounded text-orange-400 overflow-x-auto border border-white/10">
                                            {event.payload}
                                          </pre>
                                        </div>
                                      )}
                                      
                                      {event.eventType === 'response' && event.responseStatus && (
                                        <div className="mb-2 flex items-center gap-2">
                                          <div className="text-[10px] text-muted-foreground uppercase">Status:</div>
                                          <Badge variant="outline" className={`text-[10px] h-5 ${event.responseStatus >= 400 ? 'text-destructive border-destructive' : 'text-primary border-primary'}`}>
                                            {event.responseStatus}
                                          </Badge>
                                        </div>
                                      )}
                                      {event.eventType === 'response' && event.responseHeaders && (
                                        <div className="mb-2">
                                          <div className="text-[10px] text-muted-foreground mb-1 uppercase">Headers</div>
                                          <pre className="bg-black p-2 rounded text-blue-400 overflow-x-auto border border-white/10">
                                            {event.responseHeaders}
                                          </pre>
                                        </div>
                                      )}
                                      {event.eventType === 'response' && event.responseBody && (
                                        <div>
                                          <div className="text-[10px] text-muted-foreground mb-1 uppercase">Body Snippet</div>
                                          <pre className="bg-black p-2 rounded text-gray-400 overflow-x-auto border border-white/10 max-h-40">
                                            {event.responseBody}
                                          </pre>
                                        </div>
                                      )}
                                    </AccordionContent>
                                  </AccordionItem>
                                </Accordion>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
