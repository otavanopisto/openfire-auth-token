/*
 *  A signed token auth provider for OpenFire
 *  Copyright (C) 2017 Otavan opisto
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package fi.otavanopisto.openfire.auth.token;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.ConnectionException;
import org.jivesoftware.openfire.auth.InternalUnauthenticatedException;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.Log;

@SuppressWarnings("deprecation")
public class SignedTokenAuthProvider implements AuthProvider {

    @Override
    public void
        authenticate(String user, String password)
    throws
        UnauthorizedException,
        ConnectionException,
        InternalUnauthenticatedException
    {
        Log.setDebugEnabled(true);
        try {
            String timestampMaxDiffString = JiveGlobals.getProperty(
                    "fi.otavanopisto.openfire.auth.token.timestamp_max_diff",
                    "");
            long timestampMaxDiff;
            try {
                timestampMaxDiff = Long.valueOf(timestampMaxDiffString);
            } catch (NumberFormatException ex) {
                Log.error("Invalid timestamp max diff", ex);
                timestampMaxDiff = 15;
            }

            String[] parts = password.split(",");

            if (parts.length != 3) {
                Log.debug("Ill-formed password");
                throw new UnauthorizedException("Ill-formed password");
            }

            String pwTimestamp = parts[0];
            String pwUser = parts[1];
            String pwSignature = parts[2];
            String payload = pwTimestamp + "," + pwUser;

            try {
              if (!verifyMessage(payload, pwSignature)) {
                  Log.debug("Invalid signature");
                  throw new UnauthorizedException("Invalid signature");
              }
            } catch ( NoSuchAlgorithmException
                    | InvalidKeySpecException
                    | InvalidKeyException
                    | SignatureException ex) {
              Log.error(ex);
              throw new RuntimeException(ex);
            }

            long timestamp;
            try {
                timestamp = Long.parseLong(pwTimestamp);
            } catch (NumberFormatException ex) {
                Log.debug("Invalid number format");
                throw new UnauthorizedException(ex);
            }

            long currentTimestamp = Instant.now().getEpochSecond();

            if (Math.abs(currentTimestamp - timestamp) > timestampMaxDiff) {
                Log.debug("Expired token");
                throw new UnauthorizedException("Expired token");
            }

            if (!StringUtils.equalsIgnoreCase(user, pwUser)) {
                Log.debug("Invalid user in token");
                throw new UnauthorizedException("Invalid user in token");
            }
        } finally {
            Log.setDebugEnabled(false);
        }
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
    
    private boolean verifyMessage(String message, String signature)
            throws NoSuchAlgorithmException,
                   InvalidKeySpecException,
                   SignatureException,
                   InvalidKeyException {
        String verifyKey = JiveGlobals.getProperty(
                "fi.otavanopisto.openfire.auth.token.verify_key",
                "");
        byte[] keyBytes = Base64.decodeBase64(verifyKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey key = kf.generatePublic(spec);
        byte[] hash = DigestUtils.sha256(message);
        byte[] signatureBytes = Base64.decodeBase64(signature);
        
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(key);
        sig.update(hash);
        return sig.verify(signatureBytes);
    }
}
