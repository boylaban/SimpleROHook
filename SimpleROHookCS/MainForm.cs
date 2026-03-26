using System;
using System.IO;
using System.Xml;
using System.Xml.Serialization;
using System.ComponentModel;
using System.Windows.Forms;
using System.Security.Permissions;

namespace SimpleROHookCS
{
	public partial class MainForm : Form, IDisposable
	{
		private SRHSharedData m_SharedData = null;
		private NPCLogger m_npcLogger;

		protected override CreateParams CreateParams
		{
			[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]

			get
			{
				const int  WS_EX_TOOLWINDOW = 0x80;
				const long WS_POPUP         = 0x80000000L;
				const int  WS_VISIBLE       = 0x10000000;
				const int  WS_SYSMENU       = 0x80000;
				const int  WS_MAXIMIZEBOX   = 0x10000;

				CreateParams cp = base.CreateParams;
				cp.ExStyle = WS_EX_TOOLWINDOW;
				cp.Style   = unchecked((int)WS_POPUP) | WS_VISIBLE | WS_SYSMENU | WS_MAXIMIZEBOX;
				cp.Width   = 0;
				cp.Height  = 0;

				return cp;
			}
		}

		public MainForm()
		{
			InitializeComponent();
			m_SharedData = new SRHSharedData();
		}

		public new void Dispose()
		{
			m_SharedData.Dispose();
			Dispose(true);
		}

		private void exitToolStripMenuItem_Click(object sender, EventArgs e)
		{
			TaskTray_notifyIcon.Visible = false;
			Application.Exit();
		}

		private void playMusicOnClientStreamPlayerToolStripMenuItem_Click(object sender, EventArgs e)
		{
			string musicfilename = m_SharedData.musicfilename;
			var openFileDialog = new OpenFileDialog();

			openFileDialog.Title            = "Ragnarok Online BGM";
			openFileDialog.InitialDirectory = musicfilename;
			openFileDialog.CheckFileExists  = true;
			openFileDialog.Multiselect      = false;
			openFileDialog.FileName         = musicfilename;
			openFileDialog.Filter           = "mp3 file|*.mp3|wave file|*.wav";
			openFileDialog.ShowReadOnly     = false;

			if (openFileDialog.ShowDialog() == DialogResult.OK)
			{
				m_SharedData.musicfilename = openFileDialog.FileName;
				m_SharedData.executeorder  = true;
			}
		}

		private void UpdateCheckMenu()
		{
			playMusicOnClientStreamPlayerToolStripMenuItem.Enabled = (m_SharedData.g_hROWindow == 0) ? false : true;
			packetLogToolStripMenuItem.Checked = m_SharedData.write_packetlog;
			freeMouseToolStripMenuItem.Checked = m_SharedData.freemouse;

			cast_range_ToolStripTrackBar.Value = m_SharedData.cast_range;
			Set_CastRangeValue_castRangeToolStripMenuItem(m_SharedData.cast_range);

			ground_zbias_ToolStripTrackBar.Value = m_SharedData.ground_zbias;
			Set_ZBiasValue_groundZBiasToolStripMenuItem(m_SharedData.ground_zbias);

			alphaLeveltoolStripTrackBar.Value = m_SharedData.alphalevel;
			Set_AlphaLevelValue_alphaLeveltoolStripMenuItem(m_SharedData.alphalevel);

			showM2EToolStripMenuItem.Checked       = m_SharedData.m2e;
			showBBEtoolStripMenuItem.Checked       = m_SharedData.bbe;
			showDeadCelltoolStripMenuItem.Checked  = m_SharedData.deadcell;
			showChatScopetoolStripMenuItem.Checked = m_SharedData.chatscope;
			showCastRangetoolStripMenuItem.Checked = m_SharedData.castrange;

			CPUCooler_toolStripTrackBar.Value = m_SharedData.cpucoolerlevel;
			Set_CPUCoolerText_toolStripMenuItem(m_SharedData.cpucoolerlevel);

			fixWindowModeVsyncWaitToolStripMenuItem.Checked                    = m_SharedData.fix_windowmode_vsyncwait;
			showFpsToolStripMenuItem.Checked                                   = m_SharedData.show_framerate;
			showObjectInformationToolStripMenuItem.Checked                     = m_SharedData.objectinformation;
			kHzAudioModeonBootToolStripMenuItem.Checked                        = m_SharedData._44khz_audiomode;
			chainloadDinputdllasiForDinputfreeRagexesToolStripMenuItem.Checked = m_SharedData.chainload;

			nPCLoggerToolStripMenuItem.Checked = m_npcLogger.Visible;
		}

		private void kHzAudioModeonBootToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData._44khz_audiomode = tsm.Checked;
		}

		private void packetLogToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.write_packetlog = tsm.Checked;
		}

		private void freeMouseToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.freemouse = tsm.Checked;
		}

		private void showBBEtoolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.bbe = tsm.Checked;
		}

		private void showDeadCelltoolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.deadcell = tsm.Checked;
		}

		private void showChatScopetoolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.chatscope = tsm.Checked;
		}

		private void showCastRangetoolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.castrange = tsm.Checked;
		}

		private void showM2EToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.m2e = tsm.Checked;
		}

		private void showFpsToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.show_framerate = tsm.Checked;
		}

		private void showObjectInformationToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.objectinformation = tsm.Checked;
		}

		private void fixWindowModeVsyncWaitToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.fix_windowmode_vsyncwait = tsm.Checked;
		}

		private void aboutSimpleROHookToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var aboutbox = new SRHAboutBox();
			aboutbox.ShowDialog();
		}

		private void TaskTray_contextMenuStrip_Opening(object sender, CancelEventArgs e)
		{
			UpdateCheckMenu();
		}

		private void cast_range_ToolStripTrackBar_Update(object sender, EventArgs e)
		{
			ToolStripTrackBar tsTrackbar = (ToolStripTrackBar)sender;
			m_SharedData.cast_range = tsTrackbar.Value;

			Set_CastRangeValue_castRangeToolStripMenuItem(m_SharedData.cast_range);
		}

		private void Set_CastRangeValue_castRangeToolStripMenuItem(int value)
		{
			castRangeToolStripMenuItem.Text = String.Format("Cast Range: {0}", value);
		}

		private void ground_zbias_ToolStripTrackBar_Update(object sender, EventArgs e)
		{
			ToolStripTrackBar tsTrackbar = (ToolStripTrackBar)sender;
			m_SharedData.ground_zbias = tsTrackbar.Value;

			Set_ZBiasValue_groundZBiasToolStripMenuItem(m_SharedData.ground_zbias);
		}

		private void Set_ZBiasValue_groundZBiasToolStripMenuItem(int value)
		{
			groundZBiasToolStripMenuItem.Text = String.Format("Ground Z Bias: {0}", value);
		}

		private void CPUCooler_toolStripTrackBar_Update(object sender, EventArgs e)
		{
			ToolStripTrackBar tsTrackbar = (ToolStripTrackBar)sender;
			m_SharedData.cpucoolerlevel = tsTrackbar.Value;

			Set_CPUCoolerText_toolStripMenuItem(m_SharedData.cpucoolerlevel);
		}

		private void Set_CPUCoolerText_toolStripMenuItem(int value)
		{
			if (value == 0)
			{
				CPUCoolerText_toolStripMenuItem.Text = "CPU Cooler: Off";
			}
			else if (value == 1)
			{
				CPUCoolerText_toolStripMenuItem.Text = String.Format("CPU Cooler: Low", value);
			}
			else if (value == 2)
			{
				CPUCoolerText_toolStripMenuItem.Text = String.Format("CPU Cooler: Mid", value);
			}
			else if (value == 3)
			{
				CPUCoolerText_toolStripMenuItem.Text = String.Format("CPU Cooler: Max", value);
			}
		}

		private void alphaLeveltoolStripTrackBar_Update(object sender, EventArgs e)
		{
			ToolStripTrackBar tsTrackbar = (ToolStripTrackBar)sender;
			m_SharedData.alphalevel = tsTrackbar.Value;

			Set_AlphaLevelValue_alphaLeveltoolStripMenuItem(m_SharedData.alphalevel);
		}

		private void Set_AlphaLevelValue_alphaLeveltoolStripMenuItem(int value)
		{
			alphaLeveltoolStripMenuItem.Text = String.Format("Alpha Level: {0}", value);
		}

		private void InitTaskTrayMenu()
		{
			cast_range_ToolStripTrackBar.SetMinMax(0, 30);
			cast_range_ToolStripTrackBar.SetTickFrequency(1);
			cast_range_ToolStripTrackBar.SetChangeValue(1, 4);

			ground_zbias_ToolStripTrackBar.SetMinMax(0, 16);
			ground_zbias_ToolStripTrackBar.SetTickFrequency(1);
			ground_zbias_ToolStripTrackBar.SetChangeValue(1, 4);

			alphaLeveltoolStripTrackBar.SetMinMax(0, 255);
			alphaLeveltoolStripTrackBar.SetTickFrequency(4);
			alphaLeveltoolStripTrackBar.SetChangeValue(1, 16);

			CPUCooler_toolStripTrackBar.SetMinMax(0, 3);
			CPUCooler_toolStripTrackBar.SetTickFrequency(1);
			CPUCooler_toolStripTrackBar.SetChangeValue(1, 4);
		}

		private void Window_Load(object sender, EventArgs e)
		{
			InitTaskTrayMenu();

			string curentdirstr = System.IO.Directory.GetCurrentDirectory() + "\\config.ini";
			m_SharedData.configfilepath = curentdirstr;

			if (!File.Exists("config.ini"))
			{
				using (StreamWriter w = new StreamWriter(@"config.ini"))
				{
					#region config.ini
					w.WriteLine(@"
;//----------------------------------------------------------------------------
; Edit SimpleROHook settings from config.xml
;
; Toxn's M2E Configuration
;
; M2E
; Shows area of effects
; How to edit colors
; Edit values after 0x
; Example = 0xAARRGGBB
;
; AA:Alpha 00-FF (00:0%---7F:50%---FF:100%)
; RR:Red   00-FF (0-255)
; GG:Green 00-FF (0-255)
; BB:Blue  00-FF (0-255)
;----------------------------------------------------------------------------//

[Misc Color]
; Alpha is ignored for these - use the alpha level option in the GUI
Deadcell = 0x00FF00FF
Chatscope = 0x0000FF00
Castrange = 0x007F00FF
Gutterline = 0x00FF0000
Demigutter = 0x000000FF

[M2E]
; Safety Wall
Skill007E = 0xBFFF00FF

; Fire Wall
Skill007F = 0x7F880000

; Warp Portal
Skill0080 = 0x7FFFFFFF
Skill0081 = 0x7FFFFFFF
;
Skill0082 = 0x7F888888

; Sanctuary
Skill0083 = 0x7F33FF66

; Magnus Exorcismus
Skill0084 = 0x7ED1363

; Pneuma
Skill0085 = 0xFF00EEFF

; Exploding Dragon
; Heaven's Drive
; Thunderstorm
; Meteor Storm
; Storm Gust
; Lord of Vermilion
; Dark Grand Cross
; Grand Cross
Skill0086 = 0x7F006688

; Fire Pillar
Skill0087 = 0x7F888800
Skill0088 = 0x7F888800

; Sheltering Bliss
Skill0089 = 0x7F888888
;
Skill008A = 0x7F888888
Skill008B = 0x7F888888
Skill008C = 0x7F888888

; Ice Wall
Skill008D = 0x7F3771FA

; Quagmire
Skill008E = 0x7F00CC33

; Blast Mine
Skill008F = 0x7F888888

; Skid Trap
Skill0090 = 0x7F888888

; Ankle Snare
Skill0091 = 0x7F000000

; Venom Dust
Skill0092 = 0x7F660066

; Land Mine
Skill0093 = 0x7F888888

; Shockwave Trap
Skill0094 = 0x7F888888

; Sandman
Skill0095 = 0x7F888888

; Flasher
Skill0096 = 0x7F888888

; Freezing Trap
Skill0097 = 0x7F888888

; Claymore Trap
Skill0098 = 0x7F888888

; Talkie Box
Skill0099 = 0x7F888888

; Volcano
Skill009A = 0x7FCC0000

; Deluge
Skill009B = 0x7F0033CC

; Whirlwind
Skill009C = 0x7F00CC66

; Magnetic Earth
Skill009D = 0x7FFA00F6

; Lullaby
Skill009E = 0x7F888888

; Mental Sensing
Skill009F = 0x7F888888

; Down Tempo
Skill00A0 = 0x7F888888

; Battle Theme
Skill00A1 = 0x7F888888

; Harmonic Lick
Skill00A2 = 0x7F888888

; Classical Pluck
Skill00A3 = 0x7F46065C

; Power Cord
Skill00A4 = 0x5F888888

; Acoustic Rhythm
Skill00A5 = 0x5F888888

; Unchained Serenade
Skill00A6 = 0x7FEDE4E4

; Perfect Tablature
Skill00A7 = 0x5F3417EE

; Impressive Riff
Skill00A8 = 0x7FFF0073

; Magic Strings
Skill00A9 = 0xBF0099FF

; Song of Lutie
Skill00AA = 0x7FFFEE00

; Hip Shaker
Skill00AB = 0x7F47D543

; Focus Ballet
Skill00AC = 0x7F47D543

; Slow Grace
Skill00AD = 0x7F00FF00

; Lady Luck
Skill00AE = 0x7F47D543

; Gypsy's Kiss
Skill00AF = 0x7FA200FF

; Scribble
Skill00B0 = 0x7F888888

; Bomb
Skill00B1 = 0xBFFF0000

; Come to me, honey~
; Mom, Dad, I miss you!
; Romantic Rendezvous
Skill00B2 = 0x7F888888

; Battle Chant
Skill00B3 = 0x7F1ADEE8

; Basilica
Skill00B4 = 0x7F888888

; Lunar Heat
; Stellar Heat
; Solar Heat
Skill00B5 = 0x7F888888

; Blinding Mist
Skill00B6 = 0xBF696464

; Fiber Lock
Skill00B7 = 0xBFC9C5C5

; Gravitational Field
Skill00B8 = 0x7F888888

; Hermode's Rod
Skill00B9 = 0x7F888888

; Desperado
Skill00BA = 0x7F888888

; Watery Evasion
Skill00BB = 0x7F888888

; Flip Tatami
Skill00BC = 0x7F888888

; Blaze Shield
Skill00BD = 0x7F888888

; Gunslinger Mine
Skill00BE = 0x7F888888

;//----------------------------------------------------------------------------
; 3rd Class
;----------------------------------------------------------------------------//
; Warmer
Skill00E4 = 0x7FFFFF66

; Vaccum
Skill00EB = 0x7F000000

; Manhole
Skill00CC = 0x7F000000

; Blood Lust
Skill00D0 = 0x7F663300

; Chaos Panic
Skill00CE = 0x7F660066

; Neutral Barrier
Skill00E2 = 0x7F606060

; Stealth Field
Skill00E3 = 0x7606060

; Volcanic Ash
Skill00F7 = 0x7FF6600

; Song of Despair
Skill00DE = 0x7F000000
;
;
;
;
Skill00BF = 0x7F00FF15
;
Skill00C0 = 0x7F871773
Skill00C1 = 0x7F871773
Skill00C2 = 0x7F871773
Skill00C3 = 0x7F871773
Skill00C4 = 0x7F871773
Skill00C5 = 0x7F871773
Skill00C6 = 0x7F871773
Skill00C7 = 0x7FF0796C
Skill00C8 = 0x7FF0796C
Skill00C9 = 0x7FF0796C
Skill00CA = 0x7F871773
Skill00CB = 0x7F871773
Skill00CC = 0x7F49F3FC
Skill00CD = 0x7F00FFE5
Skill00CE = 0x7FEEFF30
Skill00CF = 0x7F00FFE5
;
Skill00D0 = 0x7FFF0000
Skill00D1 = 0x7FFF00FB
Skill00D2 = 0x7F00FF15
Skill00D3 = 0x7F00FF15
Skill00D4 = 0x7F00FF15
Skill00D5 = 0x7F00FF15
Skill00D6 = 0x7F00FF15
Skill00D7 = 0x7F00FF15
Skill00D8 = 0x7F00FF15
Skill00D9 = 0x7F00FF15
Skill00DA = 0x7F00FF15
Skill00DB = 0x7F00FF15
Skill00DC = 0x7F00FF15
Skill00DD = 0x7F00FF15
Skill00DE = 0x7FE3D88F
Skill00DF = 0x7F00FF15
;
Skill00E0 = 0x7F00FFD0
Skill00E1 = 0x7F00FFD0
Skill00E2 = 0x7F00EEFF
Skill00E3 = 0x7FB700FF
Skill00E4 = 0x7F00FFD0
Skill00E5 = 0x7F00FFD0
Skill00E6 = 0x7F00FF08
Skill00E7 = 0x7F00FFD0
Skill00E8 = 0x7F00FFD0
Skill00E9 = 0x7F00FFD0
Skill00EA = 0x7F00FFD0
Skill00EB = 0x7FE3D88F
Skill00EC = 0x7F00FFD0
Skill00ED = 0x7F00FFD0
Skill00EE = 0x7F00FFD0
Skill00EF = 0x7F00FFD0
;
Skill00F0 = 0x7F888888
Skill00F1 = 0x7F888888
Skill00F2 = 0x7F888888
Skill00F3 = 0x7F888888
Skill00F4 = 0x7F888888
Skill00F5 = 0x7F888888
Skill00F6 = 0x7F888888
Skill00F7 = 0x7F752929
Skill00F8 = 0x7F888888
Skill00F9 = 0x7F888888
Skill00FA = 0x7F888888
Skill00FB = 0x7F888888
Skill00FC = 0x7F888888
Skill00FD = 0x7F888888
Skill00FE = 0x7F888888
Skill00FF = 0x7F888888
");
					#endregion
				}
			}

			if (File.Exists("config.xml"))
			{
				#region Load Config XML
				using (XmlReader reader = XmlReader.Create("config.xml"))
				{
					var configration = new Config();
					var serializer = new XmlSerializer(typeof(Config));

					configration = (Config)serializer.Deserialize(reader);

					m_SharedData.write_packetlog          = configration.write_packetlog;
					m_SharedData.freemouse                = configration.freemouse;
					m_SharedData.cast_range               = configration.cast_range;
					m_SharedData.ground_zbias             = configration.ground_zbias;
					m_SharedData.alphalevel               = configration.alphalevel;
					m_SharedData.m2e                      = configration.m2e;
					m_SharedData.bbe                      = configration.bbe;
					m_SharedData.deadcell                 = configration.deadcell;
					m_SharedData.chatscope                = configration.chatscope;
					m_SharedData.castrange                = configration.castrange;
					m_SharedData.fix_windowmode_vsyncwait = configration.fix_windowmode_vsyncwait;
					m_SharedData.show_framerate           = configration.show_framerate;
					m_SharedData.objectinformation        = configration.objectinformation;
					m_SharedData._44khz_audiomode         = configration._44khz_audiomode;
					m_SharedData.cpucoolerlevel           = configration.cpucoolerlevel;
					m_SharedData.chainload                = configration.chainload;
				}
				#endregion
			}

			m_npcLogger = new NPCLogger();
			m_npcLogger.StartPosition = FormStartPosition.Manual;
			m_npcLogger.Bounds        = Properties.Settings.Default.LoggerWinBounds;
			m_npcLogger.WindowState   = Properties.Settings.Default.LoggerWinState;

			if (Properties.Settings.Default.LoggerWinVisible)
				m_npcLogger.Show();
		}

		private void Window_FormClosing(object sender, FormClosingEventArgs e)
		{
			if (m_npcLogger.WindowState == FormWindowState.Normal)
				Properties.Settings.Default.LoggerWinBounds = m_npcLogger.Bounds;
			else
				Properties.Settings.Default.LoggerWinBounds = m_npcLogger.RestoreBounds;

			Properties.Settings.Default.LoggerWinState   = m_npcLogger.WindowState;
			Properties.Settings.Default.LoggerWinVisible = m_npcLogger.Visible;
			Properties.Settings.Default.Save();
			m_npcLogger.Hide();

			#region Save Config XML
			using (XmlTextWriter writer = new XmlTextWriter("config.xml", System.Text.Encoding.UTF8))
			{
				var configration = new Config();
				var serializer = new XmlSerializer(typeof(Config));

				configration.write_packetlog          = m_SharedData.write_packetlog;
				configration.freemouse                = m_SharedData.freemouse;
				configration.cast_range               = m_SharedData.cast_range;
				configration.ground_zbias             = m_SharedData.ground_zbias;
				configration.alphalevel               = m_SharedData.alphalevel;
				configration.m2e                      = m_SharedData.m2e;
				configration.bbe                      = m_SharedData.bbe;
				configration.deadcell                 = m_SharedData.deadcell;
				configration.chatscope                = m_SharedData.chatscope;
				configration.castrange                = m_SharedData.castrange;
				configration.fix_windowmode_vsyncwait = m_SharedData.fix_windowmode_vsyncwait;
				configration.show_framerate           = m_SharedData.show_framerate;
				configration.objectinformation        = m_SharedData.objectinformation;
				configration._44khz_audiomode         = m_SharedData._44khz_audiomode;
				configration.cpucoolerlevel           = m_SharedData.cpucoolerlevel;
				configration.chainload                = m_SharedData.chainload;

				writer.Formatting = Formatting.Indented;
				serializer.Serialize(writer, configration);
			}
			#endregion
		}

		private void nPCLoggerToolStripMenuItem_Click(object sender, EventArgs e)
		{
			if (m_npcLogger.Visible)
				m_npcLogger.Hide();
			else
				m_npcLogger.Show();
		}

		private void notifyIcon_MouseClick(object sender, MouseEventArgs e)
		{
			if (e.Button == MouseButtons.Left)
			{
				m_npcLogger.TopMost = true;
				m_npcLogger.TopMost = false;
			}
		}

		private void chainloadDinputdllasiForDinputfreeRagexesToolStripMenuItem_Click(object sender, EventArgs e)
		{
			var tsm = (ToolStripMenuItem)sender;
			m_SharedData.chainload = tsm.Checked;
		}
	}

	public class Config
	{
		public Config()
		{
			write_packetlog          = false;
			freemouse                = false;
			cast_range               = 0;
			ground_zbias             = 0;
			alphalevel               = 0;
			m2e                      = true;
			bbe                      = true;
			deadcell                 = true;
			chatscope                = true;
			castrange                = true;
			fix_windowmode_vsyncwait = true;
			show_framerate           = true;
			objectinformation        = false;
			_44khz_audiomode         = false;
			cpucoolerlevel           = 0;
			chainload                = true;
		}

		public bool write_packetlog          { get; set; }
		public bool freemouse                { get; set; }
		public int  cast_range               { get; set; }
		public int  ground_zbias             { get; set; }
		public int  alphalevel               { get; set; }
		public bool m2e                      { get; set; }
		public bool bbe                      { get; set; }
		public bool deadcell                 { get; set; }
		public bool chatscope                { get; set; }
		public bool castrange                { get; set; }
		public bool fix_windowmode_vsyncwait { get; set; }
		public bool show_framerate           { get; set; }
		public bool objectinformation        { get; set; }
		public bool _44khz_audiomode         { get; set; }
		public int  cpucoolerlevel           { get; set; }
		public bool chainload                { get; set; }

		// Without serialize
		[System.Xml.Serialization.XmlIgnoreAttribute]
		public string configfilepath { get; set; }

		[System.Xml.Serialization.XmlIgnoreAttribute]
		public string musicfilename { get; set; }

		[System.Xml.Serialization.XmlIgnoreAttribute]
		public bool executeorder { get; set; }
	}
}
