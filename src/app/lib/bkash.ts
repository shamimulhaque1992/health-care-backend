import config from "../config";
import { redisClient } from "./redis";

export const getBkashIdToken = async () => {
  try {
    const IdTokenKey = "bkash:idToken";
    const RefreshTokenKey = "bkash:refreshTokenKey";

    let redisBkashIdToken = await redisClient.get(IdTokenKey);
    const redisBkashIdTokenTTL = await redisClient.ttl(IdTokenKey);
    const redisBkashRefreshToken = await redisClient.get(RefreshTokenKey);
    const redisBkashRefreshTokenTTL = await redisClient.ttl(RefreshTokenKey);

    if (
      (redisBkashIdTokenTTL <= 600 || !redisBkashIdToken) &&
      redisBkashRefreshToken &&
      redisBkashRefreshTokenTTL > 600
    ) {
      const refreshTokenResponse = await fetch(
        `${config.bkash_app_base_url}/tokenized/checkout/token/refresh`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            username: config.bkash_username,
            password: config.bkash_password,
          },
          body: JSON.stringify({
            app_key: config.bkash_app_key,
            app_secret: config.bkash_app_secret,
            refresh_token: redisBkashRefreshToken,
          }),
        },
      );
      if (!refreshTokenResponse.ok) {
        throw new Error("Bkash refresh token api failed!");
      }
      const refreshTokenResult = await refreshTokenResponse.json();

      redisBkashIdToken = refreshTokenResult.id_token as string;

      await redisClient.set(IdTokenKey, redisBkashIdToken, {
        expiration: {
          type: "EX",
          value: 60 * 60,
        },
      });
    }
    if (redisBkashIdTokenTTL > 600) {
      return redisBkashIdToken;
    }

    const response = await fetch(
      `${config.bkash_app_base_url}/tokenized/checkout/token/grant`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          username: config.bkash_username,
          password: config.bkash_password,
        },
        body: JSON.stringify({
          app_key: config.bkash_app_key,
          app_secret: config.bkash_app_secret,
        }),
      },
    );
    if (!response.ok) {
      throw new Error("Bkash Access Token Grant Failed");
    }
    const result = await response.json();

    await redisClient.set(IdTokenKey, result.id_token, {
      expiration: {
        type: "EX",
        value: 60 * 60,
      },
    });
    await redisClient.set(RefreshTokenKey, result.refresh_token, {
      expiration: {
        type: "EX",
        value: 60 * 60 * 24 * 28,
      },
    });
    redisBkashIdToken = result.id_token;

    return redisBkashIdToken;
  } catch (error) {}
};
