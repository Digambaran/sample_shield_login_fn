import { shared } from "@appblocks/node-sdk";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const sample_shield_login_fn = async (req, res) => {
  const accessTokenSecret = process.env.JWT_SECRET_ACCESS || "sample_shield_login_fn_access";
  const refreshTokenSecret = process.env.JWT_SECRET_REFRESH || "sample_shield_login_fn_refresh";
  const accessTokenExpiry = process.env.JWT_EXPIRY_ACCESS || 60 * 15;
  const refreshTokenExpiry = process.env.JWT_EXPIRY_REFRESH || 86400 * 7;

  console.log(`accessTokenSecret:${accessTokenSecret}`);
  console.log(`refreshTokenSecret:${refreshTokenSecret}`);
  console.log(`accessTokenExpiry:${accessTokenExpiry}`);
  console.log(`refreshTokenExpiry:${refreshTokenExpiry}`);

  const accessTokenExpiresAt = Math.floor(new Date().getTime() / 1000) + accessTokenExpiry;
  const refreshTokenExpiresAt = Math.floor(new Date().getTime() / 1000) + refreshTokenExpiry;

  console.log(`accessTokenExpiresAt:${accessTokenExpiresAt}`);
  console.log(`refreshTokenExpiresAt:${refreshTokenExpiresAt}`);

  const { prisma, getBody, sendResponse, redis } = await shared.getShared();
  try {
    // health check
    if (req.params["health"] === "health") {
      sendResponse(res, 200, { success: true, msg: "Health check success" });
      return;
    }

    const { email, password } = await getBody(req);

    const userData = await prisma.users.findFirst({ where: { email } });

    if (!userData) {
      // resource not found
      sendResponse(res, 200, {
        err: true,
        msg: "email not found",
        data: {
          field: "email",
          type: "userNotFound",
        },
      });
      return;
    }

    console.log(`user with email:${email} exists in records`);
    console.log(`UserData:${JSON.stringify(userData)}`);

    const isPasswordValid = bcrypt.compareSync(password, userData.password);

    if (!isPasswordValid) {
      // wrong password
      sendResponse(res, 200, {
        err: true,
        msg: "wrong credentials",
        data: {
          field: "password",
          type: "wrongCreds",
        },
      });
      return;
    }

    console.log("correct password");

    const userProvider = await prisma.user_providers.findFirst({
      where: { user_id: userData.user_id },
    });
    if (!userProvider) {
      // wrong user provider
      sendResponse(res, 200, {
        err: true,
        msg: "Wrong provider",
        data: {
          field: "email",
          type: "wrongProvider",
        },
      });
      return;
    }

    const accesstokenid = nanoid();
    const refreshtokenid = nanoid();

    const token = jwt.sign(
      {
        iss: "sample-shield-node",
        sub: userData.user_id,
        token_id: accesstokenid,
        pair_id: refreshtokenid,
        token_type: "access",
      },
      accessTokenSecret,
      { algorithm: "HS256", expiresIn: accessTokenExpiry }
    );
    const refreshtoken = jwt.sign(
      {
        iss: "sample-shield-node",
        sub: userData.user_id,
        token_id: refreshtokenid,
        pair_id: accesstokenid,
        token_type: "refresh",
      },
      refreshTokenSecret,
      { algorithm: "HS256", expiresIn: refreshTokenExpiry }
    );

    // if user try to login using same email but different provider, dont login..redirect to signup

    await redis.set(`${accesstokenid}:${userData.user_id}`, "ok", {
      EX: accessTokenExpiry,
    });
    await redis.set(`${refreshtokenid}:${userData.user_id}`, "ok", {
      EX: refreshTokenExpiry,
    });

    // "4444:user_id" for password change case
    // for password change DO:
    // check redis keys with "user_id" substr, and delete all returned key-value pair
    //  }

    // send access token, expiry of access token and refresh token, no need to give expiry of refresh token

    sendResponse(res, 200, {
      err: false,
      msg: "successfull login",
      data: {
        token,
        refreshtoken,
        expiresAt: accessTokenExpiresAt,
      },
    });
    return;
  } catch (err) {
    console.log(err, "err");
    sendResponse(res, 500, {
      err: true,
      msg: "server error",
      data: {},
    });
    return;
  }
};

export default sample_shield_login_fn;
