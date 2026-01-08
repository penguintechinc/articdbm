import { Button } from '@/components/common/Button';

export default function Index() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-b from-blue-900 to-blue-700">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-white mb-4">ArticDBM v2.0</h1>
        <p className="text-xl text-blue-100 mb-8">Database Management Platform</p>
        <div className="space-x-4">
          <Button>Dashboard</Button>
          <Button variant="outline">Documentation</Button>
        </div>
      </div>
    </div>
  );
}
