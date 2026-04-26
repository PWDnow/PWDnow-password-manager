import React, { ErrorInfo, ReactNode } from 'react';
import { ShieldAlert } from 'lucide-react';

interface Props {
  children?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null
    };
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-surface dark:bg-[#0a0a0a] p-6">
          <div className="max-w-md w-full bg-white dark:bg-[#141414] rounded-2xl shadow-xl border border-outline-variant/30 dark:border-white/10 p-8 text-center">
            <div className="w-16 h-16 bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 rounded-2xl flex items-center justify-center mx-auto mb-6">
              <ShieldAlert size={32} />
            </div>
            <h1 className="text-2xl font-headline font-bold text-black dark:text-white mb-3 tracking-tight">
              System Error Detected
            </h1>
            <p className="text-on-surface-variant text-sm mb-8">
              A critical error occurred in the application interface. Our security protocols have halted execution to prevent data corruption.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="w-full bg-black dark:bg-white text-white dark:text-black py-3.5 rounded-xl font-bold text-sm transition-all hover:opacity-90 active:scale-[0.98]"
            >
              Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
