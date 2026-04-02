import { Link, useLocation } from "wouter";
import { Terminal, Shield, Activity, Clock } from "lucide-react";
import { cn } from "@/lib/utils";

export function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();

  const navItems = [
    { href: "/", label: "Dashboard", icon: Activity },
    { href: "/scans", label: "History", icon: Clock },
  ];

  return (
    <div className="flex min-h-screen w-full bg-background flex-col md:flex-row">
      {/* Sidebar */}
      <div className="w-full md:w-64 border-r border-border bg-card flex flex-col">
        <div className="p-6 flex items-center gap-3">
          <div className="bg-primary/10 p-2 rounded-md">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h1 className="font-mono font-bold text-lg text-primary tracking-tight">SECURE<span className="text-foreground">PROBE</span></h1>
            <p className="text-xs text-muted-foreground font-mono">v1.0.0_STABLE</p>
          </div>
        </div>

        <nav className="flex-1 px-4 py-2 space-y-1">
          {navItems.map((item) => (
            <Link key={item.href} href={item.href} className="block">
              <span
                className={cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium font-mono transition-colors",
                  location === item.href || (location.startsWith('/scan/') && item.href === '/')
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                )}
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </span>
            </Link>
          ))}
        </nav>

        <div className="p-4 m-4 border border-border bg-secondary/50 rounded-md">
          <div className="flex items-center gap-2 mb-2">
            <Terminal className="h-4 w-4 text-muted-foreground" />
            <span className="text-xs font-mono text-muted-foreground uppercase">System Status</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            <span className="text-xs font-mono text-primary">All systems nominal</span>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="h-14 border-b border-border flex items-center px-6 bg-card/50 backdrop-blur-sm sticky top-0 z-10">
          <div className="flex items-center gap-2 text-sm text-muted-foreground font-mono">
            <Terminal className="h-4 w-4" />
            <span>root@secureprobe:~$ <span className="text-primary animate-pulse">_</span></span>
          </div>
        </div>
        <div className="flex-1 p-6 overflow-y-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
