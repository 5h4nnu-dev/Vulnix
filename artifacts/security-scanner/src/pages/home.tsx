import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useLocation } from "wouter";
import { Shield, ShieldAlert, ShieldCheck, Terminal, Globe, Zap, Bug, Activity, Loader2, AlertTriangle } from "lucide-react";
import { useCreateScan, useGetStatsSummary, useGetRecentActivity, getGetRecentActivityQueryKey, getGetStatsSummaryQueryKey } from "@workspace/api-client-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDistanceToNow } from "date-fns";
import { useToast } from "@/hooks/use-toast";

const scanFormSchema = z.object({
  url: z.string().url({ message: "Please enter a valid URL (e.g., https://example.com)" }),
});

export function Home() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();

  const { data: stats, isLoading: isLoadingStats } = useGetStatsSummary();
  const { data: recentActivity, isLoading: isLoadingActivity } = useGetRecentActivity();

  const createScan = useCreateScan();

  const form = useForm<z.infer<typeof scanFormSchema>>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: {
      url: "",
    },
  });

  function onSubmit(values: z.infer<typeof scanFormSchema>) {
    createScan.mutate({
      data: {
        url: values.url,
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
          title: "Scan Initiated",
          description: "Target locked. Analyzing vectors...",
        });
        setLocation(`/scan/${scan.id}`);
      },
      onError: (error) => {
        toast({
          title: "Scan Initialization Failed",
          description: error.message || "Could not start scan on target.",
          variant: "destructive",
        });
      }
    });
  }

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="flex flex-col gap-2">
        <h2 className="text-3xl font-mono font-bold tracking-tight text-primary">Target Selection</h2>
        <p className="text-muted-foreground font-mono text-sm">Enter a target URL to initiate automated vulnerability scanning.</p>
      </div>

      {/* Main Scan Form */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur">
        <CardHeader className="pb-4">
          <CardTitle className="font-mono text-lg flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            Initialize Scan Sequence
          </CardTitle>
          <CardDescription className="font-mono text-xs flex items-center gap-2 text-amber-500/80">
            <AlertTriangle className="h-3 w-3" />
            WARNING: Only scan targets you own or have explicit permission to test.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="url"
                render={({ field }) => (
                  <FormItem>
                    <div className="flex flex-col sm:flex-row gap-3">
                      <FormControl>
                        <div className="relative flex-1">
                          <Globe className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                          <Input 
                            placeholder="https://target-domain.com" 
                            className="pl-9 font-mono bg-background/50 border-input h-10"
                            {...field} 
                            disabled={createScan.isPending}
                          />
                        </div>
                      </FormControl>
                      <Button 
                        type="submit" 
                        size="lg" 
                        className="font-mono sm:w-48 bg-primary text-primary-foreground hover:bg-primary/90 h-10"
                        disabled={createScan.isPending}
                      >
                        {createScan.isPending ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            INITIALIZING...
                          </>
                        ) : (
                          <>
                            <Terminal className="mr-2 h-4 w-4" />
                            START SCAN
                          </>
                        )}
                      </Button>
                    </div>
                    <FormMessage className="font-mono text-xs" />
                  </FormItem>
                )}
              />
            </form>
          </Form>
        </CardContent>
      </Card>

      {/* Stats Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {isLoadingStats ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="bg-card/50">
              <CardContent className="p-6">
                <Skeleton className="h-4 w-24 mb-2" />
                <Skeleton className="h-8 w-16" />
              </CardContent>
            </Card>
          ))
        ) : stats ? (
          <>
            <Card className="bg-card/50 border-border/50">
              <CardContent className="p-6">
                <div className="flex items-center gap-2 text-sm font-mono text-muted-foreground mb-2">
                  <Activity className="h-4 w-4" />
                  Total Scans
                </div>
                <div className="text-3xl font-mono font-bold text-foreground">
                  {stats.totalScans.toLocaleString()}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border/50">
              <CardContent className="p-6">
                <div className="flex items-center gap-2 text-sm font-mono text-muted-foreground mb-2">
                  <Bug className="h-4 w-4 text-red-500" />
                  Total Vulnerabilities
                </div>
                <div className="text-3xl font-mono font-bold text-foreground">
                  {stats.totalVulnerabilities.toLocaleString()}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border/50">
              <CardContent className="p-6">
                <div className="flex items-center gap-2 text-sm font-mono text-muted-foreground mb-2">
                  <ShieldAlert className="h-4 w-4 text-destructive" />
                  Critical Findings
                </div>
                <div className="text-3xl font-mono font-bold text-destructive">
                  {stats.criticalCount.toLocaleString()}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-card/50 border-border/50">
              <CardContent className="p-6">
                <div className="flex items-center gap-2 text-sm font-mono text-muted-foreground mb-2">
                  <ShieldCheck className="h-4 w-4 text-primary" />
                  Avg Risk Score
                </div>
                <div className="text-3xl font-mono font-bold text-foreground">
                  {stats.avgRiskScore ? stats.avgRiskScore.toFixed(1) : "0"}
                </div>
              </CardContent>
            </Card>
          </>
        ) : null}
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-card/50 border-border/50">
          <CardHeader>
            <CardTitle className="font-mono text-lg flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Recent Targets
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingActivity ? (
              <div className="space-y-4">
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
              </div>
            ) : recentActivity?.recentScans.length ? (
              <div className="space-y-4">
                {recentActivity.recentScans.map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between p-3 rounded-md border border-border/50 bg-background/50 hover:border-primary/50 transition-colors cursor-pointer" onClick={() => setLocation(`/scan/${scan.id}`)}>
                    <div className="flex flex-col gap-1 overflow-hidden">
                      <span className="font-mono text-sm font-medium truncate">{scan.url}</span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 ml-4 flex-shrink-0">
                      <Badge variant="outline" className={`font-mono text-xs ${
                        scan.status === 'completed' ? 'border-primary text-primary' : 
                        scan.status === 'failed' ? 'border-destructive text-destructive' : 
                        'border-amber-500 text-amber-500 animate-pulse'
                      }`}>
                        {scan.status.toUpperCase()}
                      </Badge>
                      {scan.status === 'completed' && scan.riskLevel && (
                        <Badge variant="outline" className={`font-mono text-xs ${
                          scan.riskLevel === 'critical' ? 'border-destructive text-destructive bg-destructive/10' :
                          scan.riskLevel === 'high' ? 'border-orange-500 text-orange-500 bg-orange-500/10' :
                          scan.riskLevel === 'medium' ? 'border-amber-500 text-amber-500 bg-amber-500/10' :
                          scan.riskLevel === 'low' ? 'border-blue-500 text-blue-500 bg-blue-500/10' :
                          'border-gray-500 text-gray-500 bg-gray-500/10'
                        }`}>
                          {scan.riskLevel.toUpperCase()}
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center p-6 text-muted-foreground font-mono text-sm border border-dashed rounded-md">
                No recent scans found. Initialize a new sequence.
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card/50 border-border/50">
          <CardHeader>
            <CardTitle className="font-mono text-lg flex items-center gap-2">
              <Bug className="h-4 w-4" />
              Latest Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingActivity ? (
              <div className="space-y-4">
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
              </div>
            ) : recentActivity?.recentVulnerabilities.length ? (
              <div className="space-y-4">
                {recentActivity.recentVulnerabilities.map((vuln) => (
                  <div key={vuln.id} className="flex items-start gap-3 p-3 rounded-md border border-border/50 bg-background/50 hover:border-primary/50 transition-colors cursor-pointer" onClick={() => setLocation(`/scan/${vuln.scanId}`)}>
                    <div className="mt-0.5">
                      {vuln.severity === 'critical' ? <ShieldAlert className="h-4 w-4 text-destructive" /> :
                       vuln.severity === 'high' ? <ShieldAlert className="h-4 w-4 text-orange-500" /> :
                       vuln.severity === 'medium' ? <AlertTriangle className="h-4 w-4 text-amber-500" /> :
                       vuln.severity === 'low' ? <Shield className="h-4 w-4 text-blue-500" /> :
                       <ShieldCheck className="h-4 w-4 text-gray-500" />}
                    </div>
                    <div className="flex flex-col gap-1 min-w-0 flex-1">
                      <span className="font-mono text-sm font-medium truncate text-foreground">{vuln.title}</span>
                      <span className="font-mono text-xs text-muted-foreground truncate">{vuln.affectedEndpoint}</span>
                    </div>
                    <Badge variant="outline" className={`font-mono text-[10px] flex-shrink-0 ${
                          vuln.severity === 'critical' ? 'border-destructive text-destructive bg-destructive/10' :
                          vuln.severity === 'high' ? 'border-orange-500 text-orange-500 bg-orange-500/10' :
                          vuln.severity === 'medium' ? 'border-amber-500 text-amber-500 bg-amber-500/10' :
                          vuln.severity === 'low' ? 'border-blue-500 text-blue-500 bg-blue-500/10' :
                          'border-gray-500 text-gray-500 bg-gray-500/10'
                        }`}>
                      {vuln.severity.toUpperCase()}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center p-6 text-muted-foreground font-mono text-sm border border-dashed rounded-md">
                No vulnerabilities detected recently. System secure.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
