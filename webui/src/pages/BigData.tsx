import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card';
import { Link } from 'react-router-dom';
import { Database, Zap, Server, HardDrive } from 'lucide-react';

export default function BigData() {
  const services = [
    {
      name: 'Apache Spark',
      description: 'Unified analytics engine for large-scale data processing',
      icon: Zap,
      path: '/bigdata/spark',
      color: 'text-orange-600',
    },
    {
      name: 'Apache Flink',
      description: 'Stateful computations over data streams',
      icon: Database,
      path: '/bigdata/flink',
      color: 'text-purple-600',
    },
    {
      name: 'Trino',
      description: 'Distributed SQL query engine for big data',
      icon: Server,
      path: '/bigdata/trino',
      color: 'text-blue-600',
    },
    {
      name: 'Storage Backends',
      description: 'Manage S3, HDFS, and other storage systems',
      icon: HardDrive,
      path: '/bigdata/storage',
      color: 'text-green-600',
    },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold">Big Data</h1>
        <p className="text-gray-600 mt-2">Manage big data processing frameworks and storage backends</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {services.map((service) => {
          const Icon = service.icon;
          return (
            <Link key={service.path} to={service.path}>
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <div className="flex items-center space-x-3">
                    <Icon className={`h-8 w-8 ${service.color}`} />
                    <CardTitle>{service.name}</CardTitle>
                  </div>
                  <CardDescription>{service.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-gray-600">Click to manage and configure</p>
                </CardContent>
              </Card>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
