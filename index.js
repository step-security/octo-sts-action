const fs = require('fs');
const core = require('@actions/core');
const axios = require('axios');

async function validateSubscription() {
  let repoPrivate;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath && fs.existsSync(eventPath)) {
    const payload = JSON.parse(fs.readFileSync(eventPath, "utf8"));
    repoPrivate = payload?.repository?.private;
  }

  const upstream = 'octo-sts/action';
  const action = process.env.GITHUB_ACTION_REPOSITORY;
  const docsUrl = 'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions';
  core.info('');
  core.info('\u001b[1;36mStepSecurity Maintained Action\u001b[0m');
  core.info(`Secure drop-in replacement for ${upstream}`);
  if (repoPrivate === false) core.info('\u001b[32m✓ Free for public repositories\u001b[0m');
  core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`);
  core.info('');
  if (repoPrivate === false) return;
  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';
  const body = { action: action || '' };
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl;
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body, { timeout: 3000 }
    );
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 403) {
      core.error(`\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m`);
      core.error(`\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`);
      process.exit(1);
    }
    core.info('Timeout or API not reachable. Continuing to next step.');
  }
}

/**
 * Parses JWT token and extracts claims from the payload
 * @param {string} token - The JWT token to parse
 * @returns {Object} The parsed claims object
 * @throws {Error} If the token is invalid or cannot be parsed (without including token data)
 */
function parseJwtClaims(token) {
    if (!token) {
        throw new Error('Token value is missing');
    }
    const tokenParts = token.split('.');
    if (tokenParts.length !== 3) {
        throw new Error(`Invalid JWT structure: expected 3 parts, got ${tokenParts.length}`);
    }
    // Decode the payload (second part of JWT)
    let payload;
    try {
        payload = Buffer.from(tokenParts[1], 'base64url').toString('utf8');
    } catch (decodeErr) {
        // Don't include the token or decoded data in error message
        throw new Error('Failed to decode token payload: invalid base64url encoding');
    }

    let claims;
    try {
        claims = JSON.parse(payload);
    } catch (parseErr) {
        // Don't include the payload data in error message
        throw new Error('Failed to parse token payload: invalid JSON');
    }

    return claims;
}

async function fetchWithRetry(url, options = {}, retries = 3, initialDelay = 1000) {
    let attempt = 1;
    const maxAttempts = retries + 1;
    while (retries > 0) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                const errorBody = await response.text();
                throw new Error(`HTTP error! status: ${response.status}, body: ${errorBody}`);
            }
            return response;
        } catch (error) {
            console.warn(`Attempt ${attempt} failed for URL: ${url}. Error: ${error.message}`);
            const jitter = Math.floor(Math.random() * 5000);
            const delay = Math.min(2 ** attempt * initialDelay + jitter, 10000); // Limit max delay to 10 seconds
            await new Promise(resolve => setTimeout(resolve, delay));
            attempt++;
            retries--;
        }
    }
    throw new Error(`Fetch failed after ${maxAttempts} attempts for URL: ${url}.`);
}

// Only run main code if this script is executed directly (not required for testing)
if (require.main === module) {
    const actionsToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    const actionsUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;

    if (!actionsToken || !actionsUrl) {
        console.log(`::error::Missing required environment variables; have you set 'id-token: write' in your workflow permissions?`);
        process.exit(1);
    }

    const scope = process.env.INPUT_SCOPE;
    const identity = process.env.INPUT_IDENTITY;
    const domain = process.env.INPUT_DOMAIN;
    const scheme = (process.env.INPUT_SCHEME || 'https').toLowerCase();

    if (!scope || !identity) {
        console.log(`::error::Missing required inputs 'scope' and 'identity'`);
        process.exit(1);
    }

    if (scheme !== 'https' && scheme !== 'http') {
        console.log(`::error::Invalid 'scheme' input '${scheme}'; must be 'https' or 'http'`);
        process.exit(1);
    }

    (async function main() {
    // You can use await inside this function block
    try {
        await validateSubscription();
        // First fetch to get the GitHub Actions OIDC for the audience we need.
        const res = await fetchWithRetry(`${actionsUrl}&audience=${domain}`, { headers: { 'Authorization': `Bearer ${actionsToken}` } }, 5);
        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(`GitHub Actions OIDC fetch failed: ${errorText}`);
        }
        const json = await res.json();

        // Decode and print OIDC token claims for debugging
        try {
            const claims = parseJwtClaims(json.value);
            console.log('::group::OIDC Token Claims');
            console.log(JSON.stringify(claims, null, 2));
            console.log('::endgroup::');
        } catch (decodeErr) {
            console.log(`::error::Invalid OIDC token: ${decodeErr.message}`);
            throw new Error(`Failed to decode OIDC token: ${decodeErr.message}`);
        }

        // Now fetch the token from OctoSTS
        const scopes = [scope];
        // Pass scopes as a comma-separated string in the URL
        const scopesParam = scopes.join(',');
        const res2 = await fetchWithRetry(`${scheme}://${domain}/sts/exchange?scope=${scope}&scopes=${scopesParam}&identity=${identity}`, { headers: { 'Authorization': `Bearer ${json.value}` } });
        if (!res2.ok) {
            const errorText = await res2.text();
            throw new Error(`OctoSTS fetch failed: ${errorText}`);
        }
        const json2 = await res2.json();

        if (!json2.token) { console.log(`::error::${json2.message}`); process.exit(1); }
        const tok = json2.token;

        const crypto = require('crypto');
        const tokHash = crypto.createHash('sha256').update(tok).digest('hex');
        console.log(`Token hash: ${tokHash}`);

        console.log(`::add-mask::${tok}`);
        const fs = require('fs');
        fs.appendFile(process.env.GITHUB_OUTPUT, `token=${tok}`, function (err) { if (err) throw err; }); // Write the output.
        fs.appendFile(process.env.GITHUB_STATE, `token=${tok}`, function (err) { if (err) throw err; }); // Write the state, so the post job can delete the token.
    } catch (err) {
        console.log(`::error::${err.stack}`); process.exit(1);
    }
    })();
}

// Export for testing
module.exports = { parseJwtClaims, validateSubscription };
