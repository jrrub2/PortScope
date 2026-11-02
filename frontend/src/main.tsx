import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './index.css';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
class ErrorBoundary extends React.Component<{children:React.ReactNode},{error:string|null}>{
  state:{error:string|null}={error:null};
  static getDerivedStateFromError(error:Error){return {error:error.message};}
  render(){return this.state.error?<main className="mx-auto max-w-xl p-8"><Alert variant="destructive"><AlertTitle>PortScope could not render this workspace</AlertTitle><AlertDescription className="break-words">{this.state.error}</AlertDescription></Alert><Button className="mt-4" onClick={()=>location.reload()}>Reload workspace</Button><p className="mt-3 text-sm text-muted-foreground">No processes or port settings were changed.</p></main>:this.props.children;}
}
createRoot(document.getElementById('root')!).render(<ErrorBoundary><App/></ErrorBoundary>);
