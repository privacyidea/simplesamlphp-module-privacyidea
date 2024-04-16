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
/**
 * Logging interface. This is used to relay the log
 * messages of the PHP-Client to the logger
 * implementation of the project that uses the client.
 */
interface PILog
{
    public function piDebug($message);

    public function piError($message);
}