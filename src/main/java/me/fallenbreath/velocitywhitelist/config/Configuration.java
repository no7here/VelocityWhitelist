package me.fallenbreath.velocitywhitelist.config;

import com.google.common.base.Supplier;
import com.google.common.collect.Maps;
import me.fallenbreath.velocitywhitelist.IdentifyMode;
import me.fallenbreath.velocitywhitelist.PluginMeta;
import me.fallenbreath.velocitywhitelist.utils.FileUtils;
import org.slf4j.Logger;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class Configuration
{
	private static final int CONFIG_VERSION = 2;

	private final Map<String, Object> options = Maps.newConcurrentMap();
	private final Logger logger;
	private final Path configFilePath;
	private final Supplier<Boolean> proxyOnlineModeGetter;

	private IdentifyMode identifyMode = IdentifyMode.DEFAULT;

	public Configuration(Logger logger, Path configFilePath, Supplier<Boolean> proxyOnlineModeGetter)
	{
		this.logger = logger;
		this.configFilePath = configFilePath;
		this.proxyOnlineModeGetter = proxyOnlineModeGetter;
	}

	@SuppressWarnings("unchecked")
	public void load(String yamlContent)
	{
		// Parse before touching the active options, so a malformed config
		// during a reload keeps the previous state enforced instead of disabling everything
		Map<String, Object> loadedOptions = new Yaml().loadAs(yamlContent, this.options.getClass());

		this.options.clear();
		if (loadedOptions != null)  // an empty config file parses to null
		{
			this.options.putAll(loadedOptions);
		}
		this.migrate();

		this.identifyMode = this.makeIdentifyMode();
		this.warnAboutRiskyOptions();
	}

	public void reload() throws IOException
	{
		String content = Files.readString(this.configFilePath);
		this.load(content);
	}

	/**
	 * Returns the current value of the given option, or the given default if the option is absent
	 */
	private Object option(String key, Object defaultValue)
	{
		Object value = this.options.get(key);
		return value != null ? value : defaultValue;
	}

	private void migrate()
	{
		Object versionObj = this.options.get("_version");  // key used by config v1
		if (versionObj == null)
		{
			versionObj = this.options.get("version");
		}
		int version = versionObj instanceof Number number ? number.intValue() : 0;
		if (version >= CONFIG_VERSION)
		{
			return;
		}

		this.logger.warn("Migrating config file from {} to v{}", version == 0 ? "a legacy version" : "v" + version, CONFIG_VERSION);
		this.logger.warn("Please read the documentation for more information: {}", PluginMeta.REPOSITORY_URL);

		// Configs from before the uuid default switch behaved as name mode when identify_mode was absent,
		// so "name" must stay the fallback here, or migration would silently stop name-based lists from matching.
		// uuid is the default for newly generated configs only.
		Map<String, Object> newOptions = Maps.newLinkedHashMap();
		newOptions.put("version", CONFIG_VERSION);
		newOptions.put("identify_mode", this.option("identify_mode", "name"));
		newOptions.put("whitelist_enabled", this.option("whitelist_enabled", this.option("enabled", true)));
		newOptions.put("whitelist_kick_message", this.option("whitelist_kick_message", this.option("kick_message", "You are not in the whitelist!")));
		newOptions.put("blacklist_enabled", this.option("blacklist_enabled", this.option("enabled", true)));
		newOptions.put("blacklist_kick_message", this.option("blacklist_kick_message", "You are banned from the server!"));
		newOptions.put("ipban_enabled", this.option("ipban_enabled", true));
		newOptions.put("ipban_kick_message", this.option("ipban_kick_message", "Your IP address is banned from the server!"));

		Object blacklistOnIpBanJoin = this.options.get("blacklist_on_ipban_join");
		if (blacklistOnIpBanJoin == null)
		{
			blacklistOnIpBanJoin = this.defaultBlacklistOnIpBanJoin();
		}
		newOptions.put("blacklist_on_ipban_join", blacklistOnIpBanJoin);

		this.options.clear();
		this.options.putAll(newOptions);
		try
		{
			// this.options is a concurrent map and does not preserve insertion order, so dump the ordered map
			FileUtils.dumpYaml(this.configFilePath, newOptions);
		}
		catch (IOException e)
		{
			this.logger.warn("Could not save the migrated configuration file", e);
		}
	}

	private boolean defaultBlacklistOnIpBanJoin()
	{
		if (this.isProxyOnlineMode())
		{
			return true;
		}
		logOfflineModeAutoDisable(this.logger);
		return false;
	}

	/**
	 * Shared warning for the two places that flip blacklist_on_ipban_join off for offline-mode proxies:
	 * config migration, and fresh config generation in the plugin bootstrap
	 */
	public static void logOfflineModeAutoDisable(Logger logger)
	{
		logger.warn("Detected that the proxy is running in offline mode - blacklist on IP ban was automatically disabled to prevent griefing");
		logger.warn("Check the config comments / README on GitHub for more information: {}", PluginMeta.REPOSITORY_URL);
	}

	private void warnAboutRiskyOptions()
	{
		if (this.isBlacklistOnIpBanJoin() && !this.isProxyOnlineMode())
		{
			this.logger.warn("blacklist_on_ipban_join is enabled, but the proxy is running in offline mode!");
			this.logger.warn("In offline mode player identities are not verified, so anyone joining from a banned IP can get an arbitrary player name blacklisted. See the config comments / README for more information");
		}
	}

	private boolean isProxyOnlineMode()
	{
		return this.proxyOnlineModeGetter.get();
	}

	private IdentifyMode makeIdentifyMode()
	{
		Object mode = this.options.get("identify_mode");
		if (mode instanceof String)
		{
			try
			{
				return IdentifyMode.valueOf(((String)mode).toUpperCase());
			}
			catch (IllegalArgumentException e)
			{
				this.logger.warn("Invalid identify mode: {}, use default value {}", mode, IdentifyMode.DEFAULT.name().toLowerCase());
			}
		}
		return IdentifyMode.DEFAULT;
	}

	public boolean isWhitelistEnabled()
	{
		Object enabled = this.options.get("whitelist_enabled");
		if (enabled instanceof Boolean)
		{
			return (Boolean)enabled;
		}
		return false;
	}

	public boolean isBlacklistEnabled()
	{
		Object enabled = this.options.get("blacklist_enabled");
		if (enabled instanceof Boolean)
		{
			return (Boolean)enabled;
		}
		return false;
	}

	public boolean isIpBanEnabled()
	{
		Object enabled = this.options.get("ipban_enabled");
		if (enabled instanceof Boolean)
		{
			return (Boolean)enabled;
		}
		return false;
	}

	public boolean isBlacklistOnIpBanJoin()
	{
		Object opt = this.options.get("blacklist_on_ipban_join");
		if (opt instanceof Boolean)
		{
			return (Boolean)opt;
		}
		return false;
	}

	public IdentifyMode getIdentifyMode()
	{
		return this.identifyMode;
	}

	public String getWhitelistKickMessage()
	{
		Object message = this.options.get("whitelist_kick_message");
		if (message instanceof String)
		{
			return (String)message;
		}
		return "You are not in the whitelist!";
	}

	public String getBlacklistKickMessage()
	{
		Object message = this.options.get("blacklist_kick_message");
		if (message instanceof String)
		{
			return (String)message;
		}
		return "You are banned from the server!";
	}

	public String getIpBanKickMessage()
	{
		Object message = this.options.get("ipban_kick_message");
		if (message instanceof String)
		{
			return (String)message;
		}
		return "Your IP address is banned from the server!";
	}
}
