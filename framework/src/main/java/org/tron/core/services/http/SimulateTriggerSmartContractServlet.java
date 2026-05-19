package org.tron.core.services.http;

import com.google.protobuf.ByteString;
import io.netty.util.internal.StringUtil;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.Collections;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.api.GrpcAPI.Return;
import org.tron.api.GrpcAPI.Return.response_code;
import org.tron.api.GrpcAPI.TransactionExtention;
import org.tron.common.runtime.ProgramResult;
import org.tron.common.utils.ByteArray;
import org.tron.core.Wallet;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.exception.ContractValidateException;
import org.tron.core.services.jsonrpc.SimulationResultEncoder;
import org.tron.core.vm.program.listener.BufferingSimulationTracer;
import org.tron.json.JSONObject;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.Protocol.TransactionInfo;
import org.tron.protos.contract.SmartContractOuterClass.TriggerSmartContract;

/**
 * Tron-native counterpart to {@code eth_simulateV1} — POST a JSON body
 * shaped like {@code wallet/triggerconstantcontract} plus two optional
 * simulation flags ({@code trace_transfers}, {@code validation}) and get
 * back a {@link TransactionExtention} JSON envelope identical in shape to
 * what {@code wallet/triggerconstantcontract} returns. Single-call,
 * head-block only.
 *
 * <p>Use this when the dApp delivers a Tron-native
 * {@code TriggerSmartContract} (e.g. through WalletConnect's
 * {@code tron_signTransaction}) and the caller needs the transaction's
 * effect previewed before asking the user to sign. Top-level TRC-10
 * endowment ({@code call_token_value}/{@code token_id}) is surfaced as a
 * synthetic {@code TRC10Transfer} entry in {@code logs[]} when
 * {@code trace_transfers} is on.
 */
@Component
@Slf4j(topic = "API")
public class SimulateTriggerSmartContractServlet extends RateLimiterServlet {

  @Autowired
  private Wallet wallet;

  protected void doGet(HttpServletRequest request, HttpServletResponse response) {
  }

  private void validateParameter(String contract) {
    JSONObject jsonObject = JSONObject.parseObject(contract);
    if (StringUtil.isNullOrEmpty(jsonObject.getString(Util.OWNER_ADDRESS))) {
      throw new InvalidParameterException(Util.OWNER_ADDRESS + " isn't set.");
    }
    if (StringUtil.isNullOrEmpty(jsonObject.getString(Util.CONTRACT_ADDRESS))) {
      throw new InvalidParameterException(Util.CONTRACT_ADDRESS + " isn't set.");
    }
  }

  private static boolean getJsonBoolean(JSONObject jsonObject, String key) {
    if (!jsonObject.containsKey(key)) {
      return false;
    }
    return Boolean.parseBoolean(jsonObject.getString(key));
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    TriggerSmartContract.Builder build = TriggerSmartContract.newBuilder();
    TransactionExtention.Builder ext = TransactionExtention.newBuilder();
    Return.Builder ret = Return.newBuilder();
    boolean visible = false;
    try {
      String contract = request.getReader().lines()
          .collect(Collectors.joining(System.lineSeparator()));
      Util.checkBodySize(contract);
      visible = Util.getVisiblePost(contract);
      validateParameter(contract);
      JsonFormat.merge(contract, build, visible);
      JSONObject jsonObject = JSONObject.parseObject(contract);

      if (!StringUtil.isNullOrEmpty(jsonObject.getString(Util.FUNCTION_SELECTOR))) {
        String selector = jsonObject.getString(Util.FUNCTION_SELECTOR);
        String parameter = jsonObject.getString(Util.FUNCTION_PARAMETER);
        String data = Util.parseMethod(selector, parameter);
        build.setData(ByteString.copyFrom(ByteArray.fromHexString(data)));
      }

      build.setCallTokenValue(Util.getJsonLongValue(jsonObject, "call_token_value"));
      build.setTokenId(Util.getJsonLongValue(jsonObject, "token_id"));
      build.setCallValue(Util.getJsonLongValue(jsonObject, "call_value"));

      boolean traceTransfers = getJsonBoolean(jsonObject, "trace_transfers");
      boolean validation = getJsonBoolean(jsonObject, "validation");

      TransactionCapsule trxCap = wallet.createTransactionCapsule(build.build(),
          ContractType.TriggerSmartContract);

      Wallet.SimulateOutcome outcome = wallet.simulateConstantContracts(
          Collections.singletonList(trxCap), traceTransfers, validation);
      BlockCapsule head = outcome.getHeadBlockCapsule();
      Wallet.SimulateCallOutcome callOutcome = outcome.getCalls().get(0);
      ProgramResult pr = callOutcome.getResult();

      ext.setTxid(ByteString.copyFrom(
          SimulationResultEncoder.syntheticTxHash(head.getBlockId().getBytes(), 0)));
      ext.setTransaction(trxCap.getInstance());
      ext.setEnergyUsed(pr.getEnergyUsed());

      byte[] hreturn = pr.getHReturn();
      if (hreturn != null) {
        ext.addConstantResult(ByteString.copyFrom(hreturn));
      }

      for (BufferingSimulationTracer.Entry entry : callOutcome.getTracerEntries()) {
        TransactionInfo.Log log = SimulationResultEncoder.entryToProtoLog(entry,
            traceTransfers, visible);
        if (log != null) {
          ext.addLogs(log);
        }
      }

      boolean reverted = pr.isRevert();
      boolean exceptioned = pr.getException() != null;
      if (reverted || exceptioned) {
        ret.setResult(false);
        if (reverted) {
          ret.setCode(response_code.CONTRACT_EXE_ERROR);
          ret.setMessage(ByteString.copyFromUtf8(
              "REVERT opcode executed"
                  + SimulationResultEncoder.tryDecodeRevertReason(hreturn)));
        } else {
          String msg = pr.getException().getMessage();
          ret.setCode(response_code.OTHER_ERROR);
          ret.setMessage(ByteString.copyFromUtf8(msg == null ? "" : msg));
        }
      } else {
        ret.setResult(true).setCode(response_code.SUCCESS);
      }
    } catch (ContractValidateException e) {
      ret.setResult(false).setCode(response_code.CONTRACT_VALIDATE_ERROR)
          .setMessage(ByteString.copyFromUtf8(e.getMessage()));
    } catch (Exception e) {
      String errString = null;
      if (e.getMessage() != null) {
        errString = e.getMessage().replaceAll("[\"]", "'");
      }
      ret.setResult(false).setCode(response_code.OTHER_ERROR)
          .setMessage(ByteString.copyFromUtf8(e.getClass() + " : " + errString));
    }
    ext.setResult(ret);
    response.getWriter().println(Util.printTransactionExtention(ext.build(), visible));
  }
}
