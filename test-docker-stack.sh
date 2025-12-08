```bash
#!/bin/bash
# test-docker-stack.sh - Quick test of NIS2 Scanner Docker stack

set -e  # Exit on error

echo "🚀 Starting Docker stack (quick mode - no Grafana)..."
docker-compose up -d

# For full stack with Grafana, use instead:
# docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d

echo "⏳ Waiting for services to be ready (15s)..."
sleep 15

echo "🔍 Running compliance scan with test_config.yaml..."
docker-compose exec -T scanner python -m nis2scan.cli scan -c test_config.yaml --profile test

echo ""
echo "📊 Checking generated metrics..."
docker-compose exec -T scanner cat /app/reports/nis2_metrics.prom | head -20

echo ""
echo "📄 Listing generated reports..."
docker-compose exec -T scanner ls -lh /app/reports/*.html | tail -5

echo ""
echo "✅ Stack is ready and tested!"
echo ""
echo "🌐 Access Points:"
echo "  📄 HTML Reports:  http://localhost:8000"
echo "  📈 Grafana:       http://localhost:3000 (admin/admin)"
echo "  🎯 Prometheus:    http://localhost:9090"
echo ""
echo "💡 To view latest report:"
LATEST_REPORT=$(docker-compose exec -T scanner ls -t /app/reports/*.html 2>/dev/null | head -1 | tr -d '\r')
if [ ! -z "$LATEST_REPORT" ]; then
    REPORT_NAME=$(basename "$LATEST_REPORT")
    echo "   http://localhost:8000/$REPORT_NAME"
fi
echo ""
echo "🛑 To stop: docker-compose down"
