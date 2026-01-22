import React from 'react';
import type { AnalysisResult } from '../../lib/types';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';
import { HeatmapHighlighter } from './HeatmapHighlighter';
import { AlertTriangle, ShieldCheck, ShieldAlert, Info, CheckCircle2, Brain } from 'lucide-react';

interface ResultDashboardProps {
  result: AnalysisResult;
  originalText?: string;
}

export const ResultDashboard: React.FC<ResultDashboardProps> = ({ result, originalText }) => {
  const isSafe = result.riskLevel === 'SAFE' || result.riskLevel === 'LOW';
  
  // New evidence field from URL analyzer (optional)
  const evidence = (result.evidence || {}) as any;

  return (
    <div className="space-y-6 animate-slide-up">
      
      {/* STATUS HEADER */}
      <div className={`rounded-2xl p-6 border ${isSafe ? 'bg-green-50 border-green-100' : 'bg-red-50 border-red-100'} flex flex-col md:flex-row gap-6 items-start md:items-center`}>
         <div className={`w-16 h-16 rounded-full flex items-center justify-center shrink-0 ${isSafe ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}`}>
            {isSafe ? <ShieldCheck className="w-8 h-8" /> : <ShieldAlert className="w-8 h-8" />}
         </div>
         <div className="flex-1">
            <div className="flex items-center gap-3 mb-1">
                <h2 className={`text-2xl font-bold ${isSafe ? 'text-green-800' : 'text-red-800'}`}>
                    {isSafe ? "Likely Safe" : "Potential Risk Detected"}
                </h2>
                <Badge variant={isSafe ? 'success' : 'danger'}>{result.riskLevel}</Badge>
            </div>
            <p className={`${isSafe ? 'text-green-700' : 'text-red-700'} text-sm`}>
                {result.scamType !== 'None' ? `Flagged as: ${result.scamType}` : "No immediate threats found in preliminary scan."}
            </p>
         </div>
         <div className="text-right hidden md:block">
             <div className="text-3xl font-bold text-brand-navy">{result.riskScore}/100</div>
             <div className="text-xs text-slate-400 uppercase tracking-wide font-bold">Risk Score</div>
         </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* MAIN SUMMARY */}
          <div className="md:col-span-2 space-y-6">
             <Card className="p-6">
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Executive Summary</h3>
                <p className="text-brand-navy text-lg leading-relaxed font-medium">
                    {result.summary}
                </p>
                
                <div className="mt-6 pt-6 border-t border-brand-border">
                    <h4 className="flex items-center gap-2 font-bold text-brand-blue mb-2">
                        <Info className="w-4 h-4" /> Recommendation
                    </h4>
                    <p className="text-slate-600 text-sm">
                        {result.action}
                    </p>
                </div>
             </Card>

             {/* BEHAVIORAL AI EVIDENCE */}
             {evidence.suspectedIntent && (
                 <Card className="p-6 bg-purple-50/50 border-purple-100">
                     <h3 className="text-sm font-bold text-purple-800 uppercase tracking-wider mb-4 flex items-center gap-2">
                         <Brain className="w-4 h-4" /> Behavioral AI Analysis
                     </h3>
                     <div className="space-y-3">
                         <div className="flex justify-between items-center text-sm">
                             <span className="text-purple-700 font-medium">Suspected Intent:</span>
                             <span className="font-bold text-brand-navy">{evidence.suspectedIntent}</span>
                         </div>
                         <div className="flex justify-between items-center text-sm">
                             <span className="text-purple-700 font-medium">Behavioral Score:</span>
                             <span className="font-bold text-brand-navy">{evidence.behavioralScore}/100</span>
                         </div>
                         {evidence.humanExplanation && (
                             <div className="text-sm text-purple-900/80 italic border-l-2 border-purple-300 pl-3 mt-2">
                                 "{evidence.humanExplanation}"
                             </div>
                         )}
                     </div>
                 </Card>
             )}

             {/* TECHNICAL DETAILS GRID */}
             {result.details && (
                <Card className="p-6">
                    <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4" /> Technical Forensics
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                        {Object.entries(result.details).map(([key, value], i) => (
                            <div key={i} className="p-3 rounded-xl bg-brand-light border border-brand-border/50">
                                <div className="text-xs text-slate-400 font-bold uppercase mb-1">{key.replace(/([A-Z])/g, ' $1').trim()}</div>
                                <div className="text-brand-navy font-mono text-xs break-all">
                                    {Array.isArray(value) ? (
                                        <div className="flex flex-col gap-1 max-h-20 overflow-y-auto">
                                            {value.map((v: any, idx: number) => (
                                                <div key={idx} className="truncate border-b border-brand-border/50 last:border-0 pb-0.5" title={String(v)}>
                                                    {idx + 1}. {String(v)}
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        typeof value === 'object' ? 'Analyzed' : String(value)
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </Card>
             )}

            {/* HIGHLIGHTS / HEATMAP */}
            {originalText && result.highlightIndices && result.highlightIndices.length > 0 && (
                <Card className="p-6">
                    <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Linguistic Triggers</h3>
                    <HeatmapHighlighter text={originalText} highlights={result.highlightIndices} />
                </Card>
            )}
          </div>

          {/* SIDEBAR */}
          <div className="space-y-6">
             {/* RED FLAGS LIST */}
             <Card className="p-6 bg-red-50/50 border-red-100">
                <h3 className="text-sm font-bold text-red-800 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" /> Risk Factors
                </h3>
                {result.redFlags && result.redFlags.length > 0 ? (
                    <ul className="space-y-3">
                        {result.redFlags.map((flag, i) => (
                            <li key={i} className="flex items-start gap-2 text-sm text-red-700">
                                <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                                {flag}
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p className="text-sm text-slate-500 italic">No specific risk flags detected.</p>
                )}
             </Card>
             
             {/* SAFE REWRITE */}
             {result.safeRewrite && (
                 <Card className="p-6 bg-brand-light">
                     <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-4">Safe Interpretation</h3>
                     <div className="text-sm text-slate-600 leading-relaxed italic border-l-2 border-brand-blue pl-4">
                         "{result.safeRewrite}"
                     </div>
                 </Card>
             )}
          </div>
      </div>

    </div>
  );
};
