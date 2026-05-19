package org.tron.core.services.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.common.BaseTest;
import org.tron.common.TestConstants;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.PublicMethod;
import org.tron.common.utils.Sha256Hash;
import org.tron.common.utils.client.utils.HttpMethed;
import org.tron.core.Wallet;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.AssetIssueCapsule;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.ContractCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.services.jsonrpc.SimulationResultEncoder;
import org.tron.core.store.StoreFactory;
import org.tron.core.vm.config.ConfigLoader;
import org.tron.core.vm.config.VMConfig;
import org.tron.core.vm.repository.Repository;
import org.tron.core.vm.repository.RepositoryImpl;
import org.tron.protos.Protocol;
import org.tron.protos.contract.AssetIssueContractOuterClass.AssetIssueContract;
import org.tron.protos.contract.SmartContractOuterClass;

@Slf4j
public class SimulateTriggerSmartContractServletTest extends BaseTest {

  private static String httpNode;
  private static boolean started = false;

  // SimpleStorage init bytecode (uint256 value; set/get/setRevert) — solc 0.8.35
  // --evm-version paris --optimize --metadata-hash none. Same constant lives in
  // EthSimulateV1IntegrationTest; runtime is init[60:] (skip the 30-byte ctor).
  private static final String SIMPLE_STORAGE_BYTECODE =
      "6080604052348015600f57600080fd5b5060f08061001e6000396000f3fe6080604052348015600f57"
          + "600080fd5b506004361060465760003560e01c80632e8f88e614604b5780633fa4f24514605c5780"
          + "6360fe47b11460765780636d4ce63c146086575b600080fd5b605a605636600460cb565b608d565b"
          + "005b606460005481565b60405190815260200160405180910390f35b605a608136600460cb565b60"
          + "0055565b6000546064565b600081905560405162461bcd60e51b815260c290600401602080825260"
          + "0490820152636e6f706560e01b604082015260600190565b60405180910390fd5b60006020828403"
          + "121560dc57600080fd5b503591905056fea164736f6c6343000823000a";
  private static final String SIMPLE_STORAGE_RUNTIME =
      SIMPLE_STORAGE_BYTECODE.substring(60);

  // Constructor selector for SimpleStorage.get() (uint256).
  private static final String SEL_GET = "6d4ce63c";

  private static final byte[] OWNER_ADDR =
      Hex.decode("41abd4b9367799eaa3197fecb144eb71de1e049abc");
  private static final byte[] CONTRACT_ADDR =
      Hex.decode("4100000000000000000000000000000000000c0de1");
  private static final long OWNER_BALANCE = 10_000_000_000L;

  // TRC-10 testing token id (>= 1_000_001 required by VMConstant.MIN_TOKEN_ID).
  private static final long TRC10_TOKEN_ID = 1_000_001L;

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @BeforeClass
  public static void init() throws Exception {
    Args.setParam(
        new String[] {"--output-directory", dbPath(), "--debug"}, TestConstants.TEST_CONF);
    Args.getInstance().needSyncCheck = false;
    Args.getInstance().setFullNodeHttpEnable(true);
    Args.getInstance().setFullNodeHttpPort(PublicMethod.chooseRandomPort());
    Args.getInstance().setP2pDisable(true);
    Args.getInstance().setSupportConstant(true);
    httpNode = String.format("%s:%d", "127.0.0.1",
        Args.getInstance().getFullNodeHttpPort());
  }

  @Before
  public void before() {
    // Enable post-Byzantium opcodes so solc 0.8.x dispatch bytecode runs.
    // ConfigLoader.disable=true prevents the dynamic-properties store from
    // resetting these flags. ENERGY_LIMIT_HARD_FORK gates the deep-copy
    // child-repository semantics that keeps per-call writes isolated.
    ConfigLoader.disable = true;
    VMConfig.initAllowTvmTransferTrc10(1);
    VMConfig.initAllowTvmConstantinople(1);
    VMConfig.initAllowTvmSolidity059(1);
    VMConfig.initAllowTvmIstanbul(1);
    VMConfig.initAllowTvmLondon(1);
    VMConfig.initAllowTvmCompatibleEvm(1);
    CommonParameter.ENERGY_LIMIT_HARD_FORK = true;

    if (!started) {
      appT.startup();
      started = true;
    }

    AccountCapsule owner = new AccountCapsule(ByteString.copyFromUtf8("owner"),
        ByteString.copyFrom(OWNER_ADDR), Protocol.AccountType.Normal, OWNER_BALANCE);
    dbManager.getAccountStore().put(OWNER_ADDR, owner);

    long headNum = 1L;
    BlockCapsule head = new BlockCapsule(headNum,
        Sha256Hash.wrap(ByteString.copyFrom(ByteArray.fromHexString(
            "0304f784e4e7bae517bcab94c3e0c9214fb4ac7ff9d7d5a937d1f40031f87b81"))),
        System.currentTimeMillis(),
        ByteString.copyFrom(OWNER_ADDR));
    dbManager.getDynamicPropertiesStore().saveLatestBlockHeaderNumber(headNum);
    dbManager.getBlockIndexStore().put(head.getBlockId());
    dbManager.getBlockStore().put(head.getBlockId().getBytes(), head);

    Repository rootRepository = RepositoryImpl.createRoot(StoreFactory.getInstance());
    rootRepository.createAccount(CONTRACT_ADDR, Protocol.AccountType.Contract);
    rootRepository.createContract(CONTRACT_ADDR, new ContractCapsule(
        SmartContractOuterClass.SmartContract.newBuilder()
            .setContractAddress(ByteString.copyFrom(CONTRACT_ADDR))
            .build()));
    rootRepository.saveCode(CONTRACT_ADDR, Hex.decode(SIMPLE_STORAGE_RUNTIME));
    rootRepository.commit();
  }

  /**
   * Plain TRC-20 read call: {@code get()} on the
   * pre-installed SimpleStorage. Verifies the common path — non-zero
   * energy_used, result.result=true, and (with trace_transfers off) an
   * empty logs list.
   */
  @Test
  public void trc20Read_succeedsAndReturnsStatusAndGasUsed() throws Exception {
    JsonObject body = new JsonObject();
    body.addProperty("owner_address", ByteArray.toHexString(OWNER_ADDR));
    body.addProperty("contract_address", ByteArray.toHexString(CONTRACT_ADDR));
    body.addProperty("data", SEL_GET);

    JsonNode result = post(body);
    JsonNode ret = result.get("result");
    assertNotNull("result envelope missing", ret);
    assertTrue("result.result should be true: " + result, ret.get("result").asBoolean());
    long energyUsed = result.path("energy_used").asLong();
    assertTrue("energy_used should be > 0: " + energyUsed, energyUsed > 0);
    JsonNode logs = result.path("logs");
    assertTrue("logs should be empty when trace_transfers off",
        logs.isMissingNode() || logs.size() == 0);
    JsonNode txid = result.get("txid");
    assertNotNull("txid missing", txid);
    assertEquals("synthetic txid is a 32-byte hex (no 0x)", 64, txid.asText().length());
  }

  /**
   * Top-level TRC-10 transfer: {@code call_token_value > 0} + {@code token_id} on a call
   * to SimpleStorage.get(). With {@code trace_transfers: true} the response
   * must contain exactly one synthetic TRC10Transfer log carrying the
   * 4 indexed topics (sig, from, to, tokenId) and the amount in data.
   */
  @Test
  public void trc10TopLevelTransfer_producesSyntheticLog() throws Exception {
    seedTrc10(500L);

    JsonObject body = new JsonObject();
    body.addProperty("owner_address", ByteArray.toHexString(OWNER_ADDR));
    body.addProperty("contract_address", ByteArray.toHexString(CONTRACT_ADDR));
    body.addProperty("data", SEL_GET);
    body.addProperty("call_token_value", 50L);
    body.addProperty("token_id", TRC10_TOKEN_ID);
    body.addProperty("trace_transfers", true);

    JsonNode result = post(body);
    assertTrue("result.result should be true: " + result,
        result.get("result").get("result").asBoolean());
    JsonNode logs = result.get("logs");
    assertNotNull("logs missing", logs);
    assertEquals("expected one synthetic TRC10Transfer log", 1, logs.size());

    JsonNode log = logs.get(0);
    JsonNode topics = log.get("topics");
    assertEquals("expected 4 indexed topics", 4, topics.size());
    assertEquals("topic[0] is TRC10Transfer sig",
        SimulationResultEncoder.TRC10_TRANSFER_TOPIC_HEX, topics.get(0).asText());
    assertEquals("topic[3] is tokenId",
        leftPad64(TRC10_TOKEN_ID), topics.get(3).asText());
    assertEquals("amount in data", leftPad64(50L), log.get("data").asText());
    assertEquals("synthetic-log address is ERC-7528 (bare hex, no 0x prefix)",
        SimulationResultEncoder.ERC7528_NATIVE_ADDRESS, log.get("address").asText());
  }

  /**
   * Validation pre-check rejects calls with {@code call_value > sender balance}.
   * Response is still HTTP 200, but {@code result.result == false} and
   * {@code result.message} (utf-8 bytes, hex-encoded) mentions insufficient
   * balance.
   */
  @Test
  public void validation_rejectsInsufficientBalance() throws Exception {
    JsonObject body = new JsonObject();
    body.addProperty("owner_address", ByteArray.toHexString(OWNER_ADDR));
    body.addProperty("contract_address", ByteArray.toHexString(CONTRACT_ADDR));
    body.addProperty("data", SEL_GET);
    body.addProperty("call_value", OWNER_BALANCE + 1);
    body.addProperty("validation", true);

    JsonNode result = post(body);
    JsonNode ret = result.get("result");
    assertNotNull("result envelope missing", ret);
    assertTrue("result.result should be absent or false (proto3 omits default): " + result,
        ret.path("result").asBoolean(false) == false);
    assertNotNull("result.code should be set on failure: " + result, ret.get("code"));
    String msgHex = ret.get("message").asText();
    String msg = new String(ByteArray.fromHexString(msgHex), java.nio.charset.StandardCharsets.UTF_8);
    assertTrue("decoded message should mention insufficient balance: " + msg,
        msg.toLowerCase(java.util.Locale.ROOT).contains("insufficient"));
  }

  private JsonNode post(JsonObject body) throws Exception {
    String url = "http://" + httpNode + "/wallet/simulatetriggersmartcontract";
    HttpResponse response = HttpMethed.createConnect(url, body);
    assertNotNull("HTTP response should not be null", response);
    String json = EntityUtils.toString(response.getEntity());
    assertEquals("expected 200 OK, body: " + json,
        200, response.getStatusLine().getStatusCode());
    return MAPPER.readTree(json);
  }

  private void seedTrc10(long ownerAmount) {
    dbManager.getDynamicPropertiesStore().saveAllowSameTokenName(1L);
    AssetIssueContract asset = AssetIssueContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(OWNER_ADDR))
        .setName(ByteString.copyFromUtf8("TRC10"))
        .setId(String.valueOf(TRC10_TOKEN_ID))
        .setTotalSupply(1_000_000_000L)
        .setTrxNum(1)
        .setNum(1)
        .build();
    AssetIssueCapsule cap = new AssetIssueCapsule(asset);
    dbManager.getAssetIssueV2Store().put(cap.createDbV2Key(), cap);

    AccountCapsule owner = dbManager.getAccountStore().get(OWNER_ADDR);
    owner.setInstance(owner.getInstance().toBuilder()
        .putAssetV2(String.valueOf(TRC10_TOKEN_ID), ownerAmount)
        .build());
    dbManager.getAccountStore().put(OWNER_ADDR, owner);
  }

  /** Left-pad a long to 32-byte uint256 hex (64 chars, no {@code 0x} prefix). */
  private static String leftPad64(long v) {
    char[] zeros = new char[64];
    java.util.Arrays.fill(zeros, '0');
    String hex = Long.toHexString(v);
    return new String(zeros, 0, 64 - hex.length()) + hex;
  }
}
