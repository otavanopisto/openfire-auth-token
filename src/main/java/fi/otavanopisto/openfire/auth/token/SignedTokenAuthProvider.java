/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fi.otavanopisto.openfire.auth.token;

import java.nio.charset.StandardCharsets;
import org.abstractj.kalium.encoders.Encoder;
import org.abstractj.kalium.keys.VerifyKey;
import org.apache.commons.lang3.StringUtils;
import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.ConnectionException;
import org.jivesoftware.openfire.auth.InternalUnauthenticatedException;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.Log;


/**
 *
 * @author Ilmo Euro <ilmo.euro@gmail.com>
 */
public class SignedTokenAuthProvider implements AuthProvider {

    @Override
    public void
        authenticate(String user, String password)
    throws
        UnauthorizedException,
        ConnectionException,
        InternalUnauthenticatedException
    {
        String verifyKeyHex = JiveGlobals.getProperty(
                "fi.otavanopisto.openfire.auth.token.verify_key",
                "");
        String timestampMaxDiffString = JiveGlobals.getProperty(
                "fi.otavanopisto.openfire.auth.token.timestamp_max_diff",
                "");
        long timestampMaxDiff;
        try {
            timestampMaxDiff = Long.valueOf(timestampMaxDiffString);
        } catch (NumberFormatException ex) {
            Log.error("Invalid timestamp max diff", ex);
            timestampMaxDiff = 10_000;
        }

        Log.setDebugEnabled(true);

        Log.debug("Verify key:" + verifyKeyHex);
        Log.debug("User:" + user);
        Log.debug("Password:" + password);

        String[] parts = password.split(",");

        if (parts.length != 3) {
            Log.debug("Ill-formed password");
            throw new UnauthorizedException("Ill-formed password");
        }

        String pwTimestamp = parts[0];
        String pwUser = parts[1];
        String pwSignature = parts[2];
        String payload = pwTimestamp + "," + pwUser;

        VerifyKey verifyKey = new VerifyKey(verifyKeyHex, Encoder.HEX);
        byte[] signature = Encoder.HEX.decode(pwSignature);
        byte[] message = payload.getBytes(StandardCharsets.UTF_8);

        if (!verifyKey.verify(message, signature)) {
            Log.debug("Invalid signature");
            throw new UnauthorizedException("Invalid signature");
        }

        long timestamp;
        try {
            timestamp = Long.parseLong(pwTimestamp);
        } catch (NumberFormatException ex) {
            Log.debug("Invalid number format");
            throw new UnauthorizedException(ex);
        }

        long currentTimestamp = System.currentTimeMillis();

        if (Math.abs(currentTimestamp - timestamp) > timestampMaxDiff) {
            Log.debug("Expired token");
            throw new UnauthorizedException("Expired token");
        }

        if (!StringUtils.equalsIgnoreCase(user, pwUser)) {
            Log.debug("Invalid user in token");
            throw new UnauthorizedException("Invalid user in token");
        }

        Log.setDebugEnabled(false);
    }

    @Override
    public String getPassword(String string) throws UserNotFoundException, UnsupportedOperationException {
        throw new UnsupportedOperationException("Not supported by backend.");
    }

    @Override
    public void setPassword(String string, String string1) throws UserNotFoundException, UnsupportedOperationException {
        throw new UnsupportedOperationException("Not supported by backend.");
    }

    @Override
    public boolean supportsPasswordRetrieval() {
        return false;
    }

    @Override
    public boolean isScramSupported() {
        return false;
    }

    @Override
    public String getSalt(String string) throws UnsupportedOperationException, UserNotFoundException {
        throw new UnsupportedOperationException("Not supported by backend.");
    }

    @Override
    public int getIterations(String string) throws UnsupportedOperationException, UserNotFoundException {
        throw new UnsupportedOperationException("Not supported by backend.");
    }

    @Override
    public String getServerKey(String string) throws UnsupportedOperationException, UserNotFoundException {
        throw new UnsupportedOperationException("Not supported by backend.");
    }

    @Override
    public String getStoredKey(String string) throws UnsupportedOperationException, UserNotFoundException {
        throw new UnsupportedOperationException("Not supported by backend.");
    }
    
}
