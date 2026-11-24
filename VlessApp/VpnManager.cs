using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Vpn;
using Windows.ApplicationModel;

namespace VlessApp
{
    public class VpnManager
    {
        public const string ProfileName = "MetroBox";

        // На Windows 10 Mobile (10.0.15063) VpnManagementAgent.AddProfileFromObjectAsync создает приватный
        // профиль в LocalState/rasphone.pbk, невидимый в системных параметрах (ms-settings:network-vpn),
        // а программный запуск через ConnectProfileAsync / ConnectProfileWithPasswordCredentialAsync
        // блокируется политикой ОС со статусом Other (E_ACCESSDENIED). Поэтому очищаем устаревший
        // локальный rasphone.pbk, чтобы всегда использовался системный профиль из параметров ОС.
        public static void CleanupBrokenPrivatePhonebook()
        {
            try
            {
                var folder = Windows.Storage.ApplicationData.Current.LocalFolder;
                string pbkPath = System.IO.Path.Combine(folder.Path, "rasphone.pbk");
                if (System.IO.File.Exists(pbkPath))
                {
                    System.IO.File.Delete(pbkPath);
                    AppLog.W("[VPN MGR] Удален неиспользуемый приватный rasphone.pbk из LocalState");
                }
            }
            catch (Exception ex)
            {
                AppLog.W($"[VPN MGR] CleanupBrokenPrivatePhonebook: {ex.Message}");
            }
        }

        public async Task ConnectVlessAsync(VlessProfile p)
        {
            WriteSettings(p);

            var mine = await FindOwnProfileAsync();
            if (mine == null)
            {
                AppLog.W("  ОТКАЗ: VPN-профиль «" + ProfileName + "» не найден в системе");
                throw new Exception("VPN-профиль не найден в системе.");
            }

            Debug.WriteLine($"[PROFILE] Использую существующий профиль '{mine.ProfileName}'.");
            try
            {
                var agent = new VpnManagementAgent();
                var dStatus = await agent.DisconnectProfileAsync(mine);
                Debug.WriteLine($"[PROFILE] Pre-connect Disconnect => {dStatus}");
                AppLog.W("  предварительное отключение профиля: " + dStatus);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PROFILE] Disconnect ignored: {ex.Message}");
                AppLog.W("  предварительное отключение не удалось (не помеха): " + ex.Message);
            }

            await Task.Delay(1000);

            try
            {
                var agent = new VpnManagementAgent();
                var st = await agent.ConnectProfileAsync(mine);
                Debug.WriteLine($"[PROFILE] Connect existing => {st}");
                // Ответ системы виден только здесь: без него «ничего не происходит»
                // после нажатия остаётся без объяснения.
                AppLog.W("  система вернула на подключение профиля: " + st);
                if (st != VpnManagementErrorStatus.Ok)
                    throw new Exception($"Ошибка подключения: {st}");
            }
            catch (Exception ex)
            {
                AppLog.W("  ОТКАЗ при запуске профиля: " + ex.Message);
                throw new Exception($"Ошибка запуска профиля: {ex.Message}");
            }
        }

        public async Task DisconnectAsync()
        {
            try
            {
                var agent = new VpnManagementAgent();
                var mine = await FindOwnProfileAsync();
                if (mine != null)
                {
                    await agent.DisconnectProfileAsync(mine);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PROFILE] Disconnect failed: {ex.Message}");
            }
        }

        public async Task<bool> HasProfileAsync()
        {
            return (await FindOwnProfileAsync()) != null;
        }

        public void WriteSettings(VlessProfile p)
        {
            var s = Windows.Storage.ApplicationData.Current.LocalSettings.Values;
            // Имя нужно фоновой задаче только для живой плитки — на подключение не влияет.
            s["v_Name"] = p.Name ?? "";
            s["v_Address"] = p.Address ?? "";
            if (!string.IsNullOrEmpty(p.Address) && System.Net.IPAddress.TryParse(p.Address, out var ip))
            {
                s["v_ServerIp"] = ip.ToString();
                s["v_ServerIps"] = ip.ToString();
                s["v_LastServerIp"] = ip.ToString();
                s["v_LastServerIpFor"] = p.Address;
            }
            s["v_Port"] = p.Port;
            s["v_Uuid"] = p.Uuid ?? "";
            s["v_Type"] = p.Type ?? "tcp";
            s["v_Security"] = p.Security ?? "reality";
            s["v_Sni"] = p.Sni ?? "";
            s["v_PublicKey"] = p.PublicKey ?? "";
            s["v_ShortId"] = p.ShortId ?? "";
            s["v_Path"] = p.Path ?? "";
            s["v_Host"] = p.Host ?? "";
            s["v_Flow"] = p.Flow ?? "";
            s["v_Alpn"] = p.Alpn ?? "";
            s["v_Fingerprint"] = !string.IsNullOrEmpty(p.Fingerprint) ? p.Fingerprint : "firefox";
            s["v_Mtu"] = p.Mtu > 0 ? p.Mtu : 1400;
            s["v_XhttpMode"] = p.Mode ?? "stream-one";
            // Второе звено цепочки (Amnezia или универсальный Multi-Hop):
            // трафик через первое звено (реле/входной узел) доводится до выходного узла,
            // а тот проверяет свои ключи REALITY / TLS.
            s["v_ChainExitHost"] = p.EffectiveExitHost ?? "";
            s["v_ChainExitPort"] = p.EffectiveExitPort;
            s["v_ChainExitUuid"] = p.EffectiveExitUuid ?? "";
            s["v_ChainExitPublicKey"] = p.EffectiveExitPublicKey ?? "";
            s["v_ChainExitSni"] = p.EffectiveExitSni ?? "";
            s["v_ChainExitShortId"] = p.EffectiveExitShortId ?? "";
            s["v_ChainExitFlow"] = p.EffectiveExitFlow ?? "";
            s["v_AwgConfig"] = p.IsAmneziaWg ? (p.AwgConfig ?? "") : "";
            // Shadowsocks/Outline: без этих трёх ключей фоновая задача не знает ни шифра,
            // ни пароля — профиль импортировался бы, но соединение не поднималось.
            s["v_SsMethod"] = p.IsShadowsocks ? (p.Method ?? "") : "";
            s["v_SsPassword"] = p.IsShadowsocks ? (p.Password ?? "") : "";
            s["v_SsPrefix"] = p.IsShadowsocks ? (p.SsPrefix ?? "") : "";
            // Адрес TUN-интерфейса, по которому интерфейс понимает, что туннель поднят.
            s["v_TunIp"] = p.IsAmneziaWg ? (AwgAddressOf(p.AwgConfig) ?? "") : "11.16.1.1";
            s["v_DebugLog"] = true;
        }

        // Первый IPv4 из строки Address в [Interface] — им поднимается TUN у AmneziaWG.
        private static string AwgAddressOf(string conf)
        {
            if (string.IsNullOrEmpty(conf)) return null;
            foreach (var rawLine in conf.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
            {
                string line = rawLine.Trim();
                if (!line.StartsWith("Address", StringComparison.OrdinalIgnoreCase)) continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                foreach (var part in line.Substring(eq + 1).Split(','))
                {
                    string ip = part.Split('/')[0].Trim();
                    if (ip.Length > 0 && ip.IndexOf(':') < 0) return ip;
                }
            }
            return null;
        }

        private static string _lastLoggedProfileSummary = "";

        public async Task<IVpnProfile> FindOwnProfileAsync()
        {
            try
            {
                var agent = new VpnManagementAgent();
                var profiles = await agent.GetProfilesAsync();

                var sb = new System.Text.StringBuilder();
                sb.Append(profiles.Count);
                for (int i = 0; i < profiles.Count; i++)
                {
                    var p = profiles[i];
                    string st = "Other";
                    if (p is VpnPlugInProfile pl)
                    {
                        try { st = pl.ConnectionStatus.ToString(); } catch { st = "Unknown"; }
                    }
                    sb.Append($"|{p.ProfileName}:{st}");
                }
                string currentSummary = sb.ToString();
                bool shouldLog = currentSummary != _lastLoggedProfileSummary;
                if (shouldLog)
                {
                    _lastLoggedProfileSummary = currentSummary;
                    AppLog.W($"[VPN MGR] Профилей в ОС: {profiles.Count}");
                }

                IVpnProfile candidate = null;

                for (int i = 0; i < profiles.Count; i++)
                {
                    var pr = profiles[i];
                    VpnManagementConnectionStatus status = VpnManagementConnectionStatus.Disconnected;
                    if (pr is VpnPlugInProfile plug)
                    {
                        try { status = plug.ConnectionStatus; } catch { }
                        if (shouldLog)
                            AppLog.W($"[VPN MGR] #{i} '{pr.ProfileName}': {status}, PFN='{plug.VpnPluginPackageFamilyName}'");
                    }
                    else
                    {
                        if (shouldLog)
                            AppLog.W($"[VPN MGR] #{i} '{pr.ProfileName}' ({pr.GetType().Name})");
                    }

                    bool nameMatch = string.Equals(pr.ProfileName, ProfileName, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pr.ProfileName, "MetroBox", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pr.ProfileName, "Metrobox", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pr.ProfileName, "VLESS Client", StringComparison.OrdinalIgnoreCase);

                    if (nameMatch)
                    {
                        if (status == VpnManagementConnectionStatus.Connected)
                        {
                            return pr;
                        }
                        if (string.Equals(pr.ProfileName, ProfileName, StringComparison.OrdinalIgnoreCase))
                        {
                            candidate = pr; // Highest priority: exact match to current ProfileName
                        }
                        else if (candidate == null)
                        {
                            candidate = pr;
                        }
                    }
                }

                if (candidate != null) return candidate;

                if (profiles.Count > 0)
                {
                    foreach (var p in profiles)
                    {
                        if (p is VpnPlugInProfile plug && !string.IsNullOrEmpty(plug.VpnPluginPackageFamilyName))
                            return p;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PROFILE] GetProfilesAsync failed: {ex.Message}");
                AppLog.W($"[VPN MGR] GetProfilesAsync failed: {ex.Message}");
            }
            return null;
        }

        // Предварительное сохранение фиктивных учетных данных (vpn/vpn) в PasswordVault для системных профилей.
        // В Windows 10 Mobile системная телефонная книга по умолчанию создает профили с UseRasCredentials=1.
        // Если в PasswordVault отсутствуют данные для имени профиля, служба RasMan возвращает ошибку 691.
        public static void EnsurePasswordVaultCredentials()
        {
            string[] knownProfileNames = { ProfileName, "MetroBox", "Metrobox", "MetroBox VPN", "VLESS Client" };
            string[] knownUsers = { "vpn", "MetroBox" };
            try
            {
                var vault = new Windows.Security.Credentials.PasswordVault();
                foreach (var name in knownProfileNames)
                {
                    foreach (var user in knownUsers)
                    {
                        try
                        {
                            vault.Retrieve(name, user);
                        }
                        catch
                        {
                            try
                            {
                                vault.Add(new Windows.Security.Credentials.PasswordCredential(name, user, "vpn"));
                                AppLog.W($"[VPN MGR] Учётные данные ({user}/vpn) сохранены в PasswordVault для профиля '{name}'");
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.W($"[VPN MGR] Предупреждение PasswordVault: {ex.Message}");
            }
        }

        public async Task<IVpnProfile> EnsureOwnProfileAsync()
        {
            CleanupBrokenPrivatePhonebook();
            EnsurePasswordVaultCredentials();
            return await FindOwnProfileAsync();
        }
    }
}