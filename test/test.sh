curl -X POST -H "Content-Type:application/json"  http://risk.iamdemo.broadcom.com:8080/UserRiskScoreEvaluator -d @sampleRequest.json
echo ""
curl -X POST -H "Content-Type:application/json"  http://risk.iamdemo.broadcom.com:8080/PostUserRiskScoreEvaluator -d @postSampleRequest.json
echo ""
