#!/usr/bin/env bash
set -euo pipefail

FABRIC_ROOT="/home/luo/fabric-network/fabric-samples/test-network"
CHANNEL_NAME="mychannel"
VERSION="1.0"
SEQUENCE="1"
CHAINCODE_PATH="/home/luo/ForPacket"

if [[ $# -lt 1 ]]; then
  echo "用法: $0 <chaincode_name> [chaincode_path] [version] [sequence]"
  echo "示例: $0 IoT10 /home/luo/ForPacket 1.0 1"
  exit 1
fi

CC_NAME="$1"
CC_LABEL="$CC_NAME"
PKG_FILE="${CC_NAME}.tar.gz"

if [[ $# -ge 2 ]]; then
  CHAINCODE_PATH="$2"
fi
if [[ $# -ge 3 ]]; then
  VERSION="$3"
fi
if [[ $# -ge 4 ]]; then
  SEQUENCE="$4"
fi

setOrg1() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="${FABRIC_ROOT}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="${FABRIC_ROOT}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
  export CORE_PEER_ADDRESS=localhost:7051
}

setOrg2() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org2MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="${FABRIC_ROOT}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="${FABRIC_ROOT}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
  export CORE_PEER_ADDRESS=localhost:9051
}

cd "$FABRIC_ROOT"

echo "=== 打包链码: $CC_NAME ==="
peer lifecycle chaincode package "$PKG_FILE" --path "$CHAINCODE_PATH" --lang golang --label "$CC_LABEL"

echo "=== 计算 package ID ==="
PACKAGE_ID=$(peer lifecycle chaincode calculatepackageid "$PKG_FILE")
echo "PACKAGE_ID=$PACKAGE_ID"

echo "=== Org1 安装 ==="
setOrg1
peer lifecycle chaincode install "$PKG_FILE"

echo "=== Org2 安装 ==="
setOrg2
peer lifecycle chaincode install "$PKG_FILE"

echo "=== Org1 审批 ==="
setOrg1
peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID "$CHANNEL_NAME" \
  --name "$CC_NAME" \
  --version "$VERSION" \
  --package-id "$PACKAGE_ID" \
  --sequence "$SEQUENCE" \
  --tls \
  --cafile "${FABRIC_ROOT}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

echo "=== Org2 审批 ==="
setOrg2
peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID "$CHANNEL_NAME" \
  --name "$CC_NAME" \
  --version "$VERSION" \
  --package-id "$PACKAGE_ID" \
  --sequence "$SEQUENCE" \
  --tls \
  --cafile "${FABRIC_ROOT}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

echo "=== 提交定义 ==="
setOrg1
peer lifecycle chaincode commit \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --channelID "$CHANNEL_NAME" \
  --name "$CC_NAME" \
  --version "$VERSION" \
  --sequence "$SEQUENCE" \
  --tls \
  --cafile "${FABRIC_ROOT}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "${FABRIC_ROOT}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
  --peerAddresses localhost:9051 \
  --tlsRootCertFiles "${FABRIC_ROOT}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

echo "=== 查询已提交定义 ==="
peer lifecycle chaincode querycommitted --channelID "$CHANNEL_NAME" --name "$CC_NAME"

echo "=== 完成 ==="
echo "chaincode name : $CC_NAME"
echo "package file   : $PKG_FILE"
echo "package id     : $PACKAGE_ID"
echo "version        : $VERSION"
echo "sequence       : $SEQUENCE"