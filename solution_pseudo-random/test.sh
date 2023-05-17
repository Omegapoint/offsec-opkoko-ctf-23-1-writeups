#!/bin/sh

valid_token="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODMyMDcyMjIsInNjb3BlcyI6WyJjYXB0dXJlIl19.OERGfbfms1F7g8kH03J0GkjN6ZvHSyJagENGrjZkvVUtBxjE5fS0X74WDQj0y3begs1dwN4e5PA6-7EmSZJcig"
hacked_token="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODMyMTIwNDksInNjb3BlcyI6WyJjYXB0dXJlIl19.fD5HCj23zrBsRnSEw8QkM1zIMYZPb1p-VBbyStTU-2VWlpE_sYeSrxwllKSoEQv-l33dS5va8ZsyTyfPhtu__A"

localhost_url="http://localhost:7071/api/Capture"
azure_url="https://lemon-pebble-07f764303.3.azurestaticapps.net/api/capture"

# curl https://lemon-pebble-07f764303.3.azurestaticapps.net/api/capture -H "Accept: application/json" -H "X-Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODMyMTIwNDksInNjb3BlcyI6WyJjYXB0dXJlIl19.fD5HCj23zrBsRnSEw8QkM1zIMYZPb1p-VBbyStTU-2VWlpE_sYeSrxwllKSoEQv-l33dS5va8ZsyTyfPhtu__A"

# curl https://lemon-pebble-07f764303.3.azurestaticapps.net/api/capture -H "Accept: application/json" -H "X-Authorization: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODMyMTIwNDksInNjb3BlcyI6WyJjYXB0dXJlIl19.fD5HCj23zrBsRnSEw8QkM1zIMYZPb1p-VBbyStTU-2VWlpE_sYeSrxwllKSoEQv-l33dS5va8ZsyTyfPhtu__A"

# Test localhost
function test_local {
    echo "Testing with generated token"
    curl $localhost_url -H "Accept: application/json" -H "x-authorization: Bearer $valid_token"
    echo ""
    echo "Testing with hacked token"
    curl $localhost_url -H "Accept: application/json" -H "x-authorization: Bearer $hacked_token"
    echo ""
}

# Test remote
function test_remote {
    echo "Testing with generated token"
    curl $azure_url -H "Accept: application/json" -H "x-authorization: Bearer $valid_token"
    echo ""
    echo "Testing with hacked token"
    curl $azure_url -H "Accept: application/json" -H "x-authorization: Bearer $hacked_token"
    echo ""
}

test_local
#test_remote
