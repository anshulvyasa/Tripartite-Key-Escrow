import crypto from 'node:crypto';

export interface AadhaarProfile {
  aadhaarNumber: string; // 12-digit mock Aadhaar UID
  phoneNumber: string;   // Registered mobile number
  name: string;
}

export interface OtpTransaction {
  txnId: string;
  aadhaarNumber: string;
  otp: string;
  createdAt: number;
  expiresAt: number;
}

export interface GenerateOtpResult {
  success: boolean;
  txnId: string;
  maskedPhone?: string;
  mockOtp?: string; // Exposed for testing simulation
  error?: string;
}

export interface VerifyOtpResult {
  success: boolean;
  aadhaarNumber?: string;
  error?: string;
}

/**
 * Simulated Aadhaar identity and OTP verification service.
 */
export class MockAadhaarService {
  private readonly profiles: Map<string, AadhaarProfile> = new Map();
  private readonly activeOtps: Map<string, OtpTransaction> = new Map();
  private readonly otpTtlMs: number;

  constructor(otpTtlMs: number = 300_000) { // 5 minutes default
    this.otpTtlMs = otpTtlMs;

    // Seed default test identities
    this.registerProfile({
      aadhaarNumber: '123456789012',
      phoneNumber: '+91-9876543210',
      name: 'Alice Sharma',
    });
    this.registerProfile({
      aadhaarNumber: '987654321098',
      phoneNumber: '+91-9123456789',
      name: 'Bob Verma',
    });
  }

  /**
   * Registers or updates an Aadhaar resident profile.
   */
  registerProfile(profile: AadhaarProfile): void {
    if (!/^\d{12}$/.test(profile.aadhaarNumber)) {
      throw new Error(`Invalid Aadhaar number format: must be 12 digits, got '${profile.aadhaarNumber}'`);
    }
    this.profiles.set(profile.aadhaarNumber, profile);
  }

  /**
   * Generates and dispatches a 6-digit OTP for the given Aadhaar UID.
   */
  generateOtp(aadhaarNumber: string): GenerateOtpResult {
    const profile = this.profiles.get(aadhaarNumber);
    if (!profile) {
      return {
        success: false,
        txnId: '',
        error: `Aadhaar UID '${aadhaarNumber}' is not registered in mock database`,
      };
    }

    const txnId = crypto.randomUUID();
    // 6-digit numeric OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const now = Date.now();

    this.activeOtps.set(txnId, {
      txnId,
      aadhaarNumber,
      otp,
      createdAt: now,
      expiresAt: now + this.otpTtlMs,
    });

    // Mask phone e.g. +91-XXXXXX3210
    const rawPhone = profile.phoneNumber;
    const masked = rawPhone.length > 4 ? `+XX-XXXXXX${rawPhone.slice(-4)}` : '+XX-XXXX';

    return {
      success: true,
      txnId,
      maskedPhone: masked,
      mockOtp: otp, // For automated testing convenience
    };
  }

  /**
   * Verifies an OTP against a transaction ID.
   * Single-use replay protection: once validated, the transaction is consumed.
   */
  verifyOtp(txnId: string, inputOtp: string): VerifyOtpResult {
    const record = this.activeOtps.get(txnId);
    if (!record) {
      return {
        success: false,
        error: 'Invalid or expired transaction ID',
      };
    }

    // Check expiration
    if (Date.now() > record.expiresAt) {
      this.activeOtps.delete(txnId);
      return {
        success: false,
        error: 'OTP has expired',
      };
    }

    // Verify OTP value
    if (record.otp !== inputOtp.trim()) {
      return {
        success: false,
        error: 'Incorrect OTP',
      };
    }

    // Consume OTP to prevent replay attacks
    this.activeOtps.delete(txnId);

    return {
      success: true,
      aadhaarNumber: record.aadhaarNumber,
    };
  }
}
