<?php
/*
 * Copyright 2024 NetKnights GmbH - lukas.matusiewicz@netknights.it
 * <p>
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3;
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace SimpleSAML\Module\privacyidea\Auth;
class PIChallenge
{
    /* @var string Type of token this challenge is for. */
    public string $type = "";

    /* @var string Message extracted from this challenge. */
    public string $message = "";

    /* @var string Image data extracted from this challenge. */
    public string $image = "";

    /* @var string TransactionId to reference this challenge in later requests. */
    public string $transactionID = "";

    /* @var string Client mode in which the challenge should be processed. */
    public string $clientMode = "";

    /* @var string Serial of token this challenge is for. */
    public string $serial = "";

    /* @var array Arbitrary attributes that can be appended to the challenge by the server. */
    public array $attributes = [];

    /* @var string WebAuthn sign request in JSON format */
    public string $webAuthnSignRequest = "";

    /* @var string U2F sign request in JSON format */
    public string $u2fSignRequest = "";
}