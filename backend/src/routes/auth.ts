import { Router, Request, Response, NextFunction } from 'express';
import { generateChallenge, verifySignature, issueJwt } from '../auth_service';
import { logger } from '../logger';
import { AppError } from '../lib/errors';

/**
 * Auth routes for Stellar wallet-based authentication.
 *
 * POST /api/auth/challenge  — Request a sign challenge for a wallet address
 * POST /api/auth/verify     — Submit signed challenge to receive a JWT
 */
export function createAuthRouter(): Router {
  const router = Router();

  router.post('/challenge', async (req: Request, res: Response, next: NextFunction) => {
    const { walletAddress } = req.body;

    if (!walletAddress || typeof walletAddress !== 'string') {
      return next(new AppError('VALIDATION_ERROR', 'walletAddress is required', 400));
    }

    try {
      const challenge = await generateChallenge(walletAddress.trim());
      logger.info('Auth challenge issued', { walletAddress });
      return res.status(200).json({ challenge });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to generate challenge';
      logger.warn('Auth challenge failed', { walletAddress, error: message });
      return next(new AppError('CHALLENGE_FAILED', message, 400));
    }
  });

  router.post('/verify', async (req: Request, res: Response, next: NextFunction) => {
    const { walletAddress, challenge, signature } = req.body;

    if (!walletAddress || !challenge || !signature) {
      return next(
        new AppError('VALIDATION_ERROR', 'walletAddress, challenge, and signature are required', 400)
      );
    }

    try {
      const isValid = await verifySignature(walletAddress.trim(), challenge, signature);

      if (!isValid) {
        logger.warn('Auth verification failed — invalid signature', { walletAddress });
        return next(new AppError('INVALID_SIGNATURE', 'Invalid signature', 401));
      }

      const token = issueJwt(walletAddress.trim());
      logger.info('Auth verification successful', { walletAddress });
      return res.status(200).json({ token });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Verification failed';
      logger.warn('Auth verify error', { walletAddress, error: message });
      return next(new AppError('VERIFICATION_FAILED', message, 401));
    }
  });

  return router;
}
