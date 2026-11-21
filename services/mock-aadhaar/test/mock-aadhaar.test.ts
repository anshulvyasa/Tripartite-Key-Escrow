import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { MockAadhaarService } from '../src/index.ts';

describe('@trivault/mock-aadhaar Unit Tests', () => {
  it('should successfully generate and verify OTP for registered resident profile', () => {
    const aadhaarService = new MockAadhaarService();

    const residentUid = '112233445566';
    aadhaarService.registerProfile({
      aadhaarNumber: residentUid,
      phoneNumber: '+91-9988776655',
      name: 'Rohan Gupta',
    });

    const otpGen = aadhaarService.generateOtp(residentUid);
    assert.strictEqual(otpGen.success, true);
    assert.ok(otpGen.txnId);
    assert.ok(otpGen.mockOtp);
    assert.match(otpGen.maskedPhone!, /\+XX-XXXXXX6655/);

    // Verify correct OTP
    const verifyResult = aadhaarService.verifyOtp(otpGen.txnId, otpGen.mockOtp!);
    assert.strictEqual(verifyResult.success, true);
    assert.strictEqual(verifyResult.aadhaarNumber, residentUid);

    // Replay attack prevention: OTP cannot be reused
    const replayResult = aadhaarService.verifyOtp(otpGen.txnId, otpGen.mockOtp!);
    assert.strictEqual(replayResult.success, false);
    assert.match(replayResult.error!, /Invalid or expired transaction ID/);
  });

  it('should reject invalid or unregistered Aadhaar UIDs', () => {
    const aadhaarService = new MockAadhaarService();

    const unregResult = aadhaarService.generateOtp('999999999999');
    assert.strictEqual(unregResult.success, false);
    assert.match(unregResult.error!, /is not registered/);
  });

  it('should reject incorrect OTP values', () => {
    const aadhaarService = new MockAadhaarService();
    const otpGen = aadhaarService.generateOtp('123456789012');

    const verifyWrong = aadhaarService.verifyOtp(otpGen.txnId, '000000');
    assert.strictEqual(verifyWrong.success, false);
    assert.match(verifyWrong.error!, /Incorrect OTP/);
  });
});
