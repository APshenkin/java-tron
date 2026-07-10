package org.tron.core.services.jsonrpc;

import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.Hash;
import org.tron.common.logsfilter.ContractEventParser;
import org.tron.common.runtime.ProgramResult;
import org.tron.common.runtime.vm.DataWord;
import org.tron.common.runtime.vm.LogInfo;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.DecodeUtil;
import org.tron.core.db.TransactionTrace;
import org.tron.core.services.jsonrpc.types.SimulateCallOutcome;
import org.tron.core.services.jsonrpc.types.SimulateCallResult;
import org.tron.core.vm.program.listener.BufferingSimulationTracer;
import org.tron.protos.Protocol.TransactionInfo;

/**
 * Shared encoder that turns a {@link SimulateCallOutcome} into a
 * {@link SimulateCallResult}, including the synthetic ERC-7528 Transfer
 * and TRC10Transfer logs produced by
 * {@link BufferingSimulationTracer}.
 *
 * <p>Used by both {@link TronJsonRpcImpl#ethSimulateV1} (which folds many
 * per-call results into a block envelope) and the Tron-native
 * {@code wallet/simulatetriggersmartcontract} servlet (which returns a
 * single flat result). Centralising the encoding here keeps log topic
 * / address / data byte layout identical between the two entry points.
 */
@Slf4j(topic = "API")
public final class SimulationResultEncoder {

  public static final String SIMULATE_BLOCK_HASH_PREFIX = "sim:";
  /** keccak256("Transfer(address,address,uint256)"). */
  public static final String TRANSFER_TOPIC_HEX =
      "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  /**
   * keccak256("TRC10Transfer(address,address,uint256,uint256)") — synthetic
   * topic[0] for TRC-10 transfer logs, distinguishing them from ERC-20
   * Transfer (same synthetic-log address, different signature).
   *
   * <p><b>Tron private extension; stable client contract.</b> This is not part of any
   * cross-chain Ethereum standard. Wallets and indexers will hard-code this hex value to
   * recognise simulated TRC-10 transfers, so the signature string must not be edited once
   * shipped. {@code SimulationResultEncoderTest#trc10TransferTopicHex_isStable} pins the
   * canonical signature with its own copy of the literal; editing the literal here without
   * updating the test fails CI.
   */
  public static final String TRC10_TRANSFER_TOPIC_HEX =
      ByteArray.toHexString(Hash.sha3(
          "TRC10Transfer(address,address,uint256,uint256)"
              .getBytes(StandardCharsets.UTF_8)));
  /** ERC-7528 native pseudo-address shared by TRX and TRC-10 synthetic logs. */
  public static final String ERC7528_NATIVE_ADDRESS =
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

  private static final String ERROR_SELECTOR = "08c379a0";
  private static final int REVERT_REASON_SELECTOR_LENGTH = 4;
  private static final int MAX_REVERT_REASON_PAYLOAD_BYTES = 4096;

  private SimulationResultEncoder() {
  }

  /** Deterministic synthetic block hash for the simulated block above the head. */
  public static byte[] syntheticBlockHash(byte[] headHash) {
    return Hash.sha3(
        (SIMULATE_BLOCK_HASH_PREFIX + ByteArray.toHexString(headHash) + ":1")
            .getBytes(StandardCharsets.UTF_8));
  }

  /** Deterministic synthetic per-call tx hash within the simulated block. */
  public static byte[] syntheticTxHash(byte[] headHash, int callIndex) {
    return Hash.sha3(
        (SIMULATE_BLOCK_HASH_PREFIX + ByteArray.toHexString(headHash) + ":"
            + callIndex).getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Encode a single {@link SimulateCallOutcome} into a
   * {@link SimulateCallResult}. The {@code logIdx} counter is mutated
   * across entries (including dropped ones — gaps in {@code logIndex} on
   * revert match geth's {@code logtracer.go:128} semantics).
   */
  public static SimulateCallResult buildCallResult(
      SimulateCallOutcome callOutcome,
      byte[] headHash,
      String simBlockHashRaw,
      long blockNumber,
      int callIndex,
      AtomicInteger logIdx,
      boolean traceTransfers) {

    ProgramResult pr = callOutcome.getResult();
    byte[] txHashBytes = syntheticTxHash(headHash, callIndex);
    String txHashRaw = ByteArray.toHexString(txHashBytes);
    String txHashHex = ByteArray.toJsonHex(txHashBytes);

    SimulateCallResult scr = new SimulateCallResult();
    scr.setReturnData(ByteArray.toJsonHex(pr.getHReturn()));
    scr.setGasUsed(ByteArray.toJsonHex(pr.getEnergyUsed()));
    scr.setTransactionHash(txHashHex);
    scr.setTransactionIndex(ByteArray.toJsonHex(callIndex));

    boolean reverted = pr.isRevert();
    boolean failed = pr.getException() != null || reverted;
    scr.setStatus(failed ? "0x0" : "0x1");

    List<TronJsonRpc.LogFilterElement> logs = new ArrayList<>();
    if (!failed) {
      byte[] contractAddr = pr.getContractAddress();
      if (contractAddr != null && contractAddr.length > 0) {
        scr.setContractAddress(ByteArray.toJsonHexAddress(contractAddr));
      }
      for (BufferingSimulationTracer.Entry entry : callOutcome.getTracerEntries()) {
        TronJsonRpc.LogFilterElement el = entryToLogFilterElement(entry, simBlockHashRaw,
            blockNumber, txHashRaw, callIndex, logIdx.getAndIncrement(), traceTransfers);
        if (el != null) {
          logs.add(el);
        }
      }
    }
    scr.setLogs(logs);

    if (failed) {
      byte[] revertData = pr.getHReturn();
      if (revertData != null && revertData.length > 0) {
        scr.setErrorData(ByteArray.toJsonHex(revertData));
      }
      if (reverted) {
        scr.setErrorMessage("REVERT opcode executed" + tryDecodeRevertReason(revertData));
      } else if (pr.getException() != null) {
        scr.setErrorMessage(pr.getException().getMessage());
      }
    }
    return scr;
  }

  public static TronJsonRpc.LogFilterElement entryToLogFilterElement(
      BufferingSimulationTracer.Entry entry, String blockHashRaw, long blockNum,
      String txHashRaw, int callIndex, int logIdx, boolean traceTransfers) {

    String addressRaw;
    List<DataWord> topics;
    String dataHex;

    if (entry.getKind() == BufferingSimulationTracer.EntryKind.TRANSFER) {
      if (!traceTransfers) {
        return null;
      }
      addressRaw = ERC7528_NATIVE_ADDRESS;
      topics = new ArrayList<>(3);
      topics.add(new DataWord(ByteArray.fromHexString(TRANSFER_TOPIC_HEX)));
      topics.add(new DataWord(entry.getFromEvm()));
      topics.add(new DataWord(entry.getToEvm()));
      dataHex = ByteArray.toHexString(new DataWord(entry.getAmount()).getData());
    } else if (entry.getKind() == BufferingSimulationTracer.EntryKind.TOKEN_TRANSFER) {
      if (!traceTransfers) {
        return null;
      }
      addressRaw = ERC7528_NATIVE_ADDRESS;
      topics = new ArrayList<>(4);
      topics.add(new DataWord(ByteArray.fromHexString(TRC10_TRANSFER_TOPIC_HEX)));
      topics.add(new DataWord(entry.getFromEvm()));
      topics.add(new DataWord(entry.getToEvm()));
      topics.add(new DataWord(entry.getTokenId()));
      dataHex = ByteArray.toHexString(new DataWord(entry.getAmount()).getData());
    } else {
      LogInfo li = entry.getLogInfo();
      byte[] addr = li.getAddress();
      if (addr != null && addr.length > 0 && addr[0] == DecodeUtil.addressPreFixByte) {
        byte[] stripped = new byte[addr.length - 1];
        System.arraycopy(addr, 1, stripped, 0, stripped.length);
        addressRaw = ByteArray.toHexString(stripped);
      } else {
        addressRaw = addr == null ? "" : ByteArray.toHexString(addr);
      }
      topics = new ArrayList<>(li.getTopics());
      dataHex = li.getData() == null ? "" : ByteArray.toHexString(li.getData());
    }

    return new TronJsonRpc.LogFilterElement(
        blockHashRaw, blockNum, txHashRaw, callIndex,
        addressRaw, topics, dataHex, logIdx, false,
        System.currentTimeMillis());
  }

  /**
   * Encode a tracer entry as a {@link TransactionInfo.Log} for the Tron-native
   * HTTP response shape (returned by {@code wallet/simulatetriggersmartcontract}).
   * Returns {@code null} when the entry is a synthetic transfer and
   * {@code traceTransfers} is false (caller skips it).
   *
   * <p>Address encoding follows {@code gettransactioninfobyid}'s convention:
   * 20-byte EVM form when {@code visible=false} (serialized as bare hex by
   * {@link JsonFormat}), 21-byte Tron-prefixed when {@code visible=true} (so
   * {@code JsonFormat} base58-encodes it).
   */
  public static TransactionInfo.Log entryToProtoLog(
      BufferingSimulationTracer.Entry entry, boolean traceTransfers, boolean visible) {
    byte[] addrEvm;
    List<ByteString> topics = new ArrayList<>(4);
    byte[] data;

    if (entry.getKind() == BufferingSimulationTracer.EntryKind.TRANSFER) {
      if (!traceTransfers) {
        return null;
      }
      addrEvm = ByteArray.fromHexString(ERC7528_NATIVE_ADDRESS);
      topics.add(ByteString.copyFrom(ByteArray.fromHexString(TRANSFER_TOPIC_HEX)));
      topics.add(ByteString.copyFrom(new DataWord(entry.getFromEvm()).getData()));
      topics.add(ByteString.copyFrom(new DataWord(entry.getToEvm()).getData()));
      data = new DataWord(entry.getAmount()).getData();
    } else if (entry.getKind() == BufferingSimulationTracer.EntryKind.TOKEN_TRANSFER) {
      if (!traceTransfers) {
        return null;
      }
      addrEvm = ByteArray.fromHexString(ERC7528_NATIVE_ADDRESS);
      topics.add(ByteString.copyFrom(ByteArray.fromHexString(TRC10_TRANSFER_TOPIC_HEX)));
      topics.add(ByteString.copyFrom(new DataWord(entry.getFromEvm()).getData()));
      topics.add(ByteString.copyFrom(new DataWord(entry.getToEvm()).getData()));
      topics.add(ByteString.copyFrom(new DataWord(entry.getTokenId()).getData()));
      data = new DataWord(entry.getAmount()).getData();
    } else {
      LogInfo li = entry.getLogInfo();
      byte[] addr = li.getAddress();
      if (addr != null && addr.length > 0 && addr[0] == DecodeUtil.addressPreFixByte) {
        byte[] stripped = new byte[addr.length - 1];
        System.arraycopy(addr, 1, stripped, 0, stripped.length);
        addrEvm = stripped;
      } else {
        addrEvm = addr == null ? new byte[20] : addr;
      }
      for (DataWord topic : li.getTopics()) {
        topics.add(ByteString.copyFrom(topic.getData()));
      }
      data = li.getData() == null ? new byte[0] : li.getData();
    }

    byte[] addrFinal = visible ? TransactionTrace.convertToTronAddress(addrEvm) : addrEvm;
    TransactionInfo.Log.Builder log = TransactionInfo.Log.newBuilder()
        .setAddress(ByteString.copyFrom(addrFinal))
        .setData(ByteString.copyFrom(data));
    log.addAllTopics(topics);
    return log.build();
  }

  public static String tryDecodeRevertReason(byte[] resData) {
    if (resData == null || resData.length <= REVERT_REASON_SELECTOR_LENGTH) {
      return "";
    }
    if (!Hex.toHexString(resData, 0, REVERT_REASON_SELECTOR_LENGTH).equals(ERROR_SELECTOR)) {
      return "";
    }

    int revertPayloadLength = resData.length - REVERT_REASON_SELECTOR_LENGTH;
    if (revertPayloadLength > MAX_REVERT_REASON_PAYLOAD_BYTES) {
      logger.debug("skip parsing oversized revert reason payload: {} bytes", revertPayloadLength);
      return "";
    }

    try {
      String reason = ContractEventParser.parseDataBytes(
          Arrays.copyOfRange(resData, REVERT_REASON_SELECTOR_LENGTH, resData.length),
          "string", 0);
      return reason.isEmpty() ? "" : ": " + reason;
    } catch (RuntimeException e) {
      logger.debug("parse revert reason failed", e);
      return "";
    }
  }
}
