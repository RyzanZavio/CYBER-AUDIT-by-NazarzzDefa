import React from 'react';
import {
  Palette,
  Eye,
  Monitor,
  Type,
  Maximize2,
  Minimize2,
  Volume2,
  VolumeX,
  Sparkles,
  RotateCcw,
  Check,
  Zap,
  Sliders,
  Sun,
  Moon,
  Tv,
  Grid,
  Shield,
  CheckCircle2,
} from 'lucide-react';
import {
  AccentColor,
  FontFamilyChoice,
  ThemePreset,
  UiDensity,
  VisualSettings,
} from '../types';
import { cyberSound } from '../utils/cyberSound';

interface VisualCustomizerProps {
  settings: VisualSettings;
  onChangeSettings: (newSettings: VisualSettings) => void;
  onResetDefaults: () => void;
  isOpen?: boolean;
  onClose?: () => void;
  isModal?: boolean;
}

export const VisualCustomizer: React.FC<VisualCustomizerProps> = ({
  settings,
  onChangeSettings,
  onResetDefaults,
  isOpen = true,
  onClose,
  isModal = true,
}) => {
  if (isModal && !isOpen) return null;

  const update = (partial: Partial<VisualSettings>) => {
    const next = { ...settings, ...partial };
    onChangeSettings(next);
    if (next.enableSoundFx) {
      cyberSound.playClick(next.soundVolume);
    }
  };

  const handleTestSound = () => {
    cyberSound.playPing('success', settings.soundVolume);
  };

  const themePresets: {
    id: ThemePreset;
    name: string;
    tagline: string;
    bgHex: string;
    accentHex: string;
    borderHex: string;
    isLight?: boolean;
  }[] = [
    {
      id: 'cyber-slate',
      name: 'Cyber Slate',
      tagline: 'Standard DevSecOps Navy & Cyan',
      bgHex: '#020617',
      accentHex: '#06b6d4',
      borderHex: '#1e293b',
    },
    {
      id: 'matrix',
      name: 'Matrix Phosphor',
      tagline: 'Hacker Emerald Green CRT',
      bgHex: '#030a04',
      accentHex: '#10b981',
      borderHex: '#0a3517',
    },
    {
      id: 'oled-black',
      name: 'OLED Pure Black',
      tagline: 'Zero-Black #000000 High Contrast',
      bgHex: '#000000',
      accentHex: '#38bdf8',
      borderHex: '#27272a',
    },
    {
      id: 'red-team',
      name: 'Red Team Ops',
      tagline: 'Adversary Simulation Crimson',
      bgHex: '#0d0407',
      accentHex: '#f43f5e',
      borderHex: '#380f1b',
    },
    {
      id: 'synthwave',
      name: 'Synthwave Neon',
      tagline: 'Cyberpunk Violet & Fuchsia',
      bgHex: '#0b0717',
      accentHex: '#c084fc',
      borderHex: '#2c1b54',
    },
    {
      id: 'amber-terminal',
      name: 'Amber 2800K',
      tagline: 'Vintage Monokai CRT Terminal',
      bgHex: '#0d0903',
      accentHex: '#fbbf24',
      borderHex: '#3d2909',
    },
    {
      id: 'light-lab',
      name: 'White Hat Lab',
      tagline: 'Daylight High-Contrast Clean Audit',
      bgHex: '#f8fafc',
      accentHex: '#0284c7',
      borderHex: '#cbd5e1',
      isLight: true,
    },
  ];

  const accents: { id: AccentColor; name: string; hex: string }[] = [
    { id: 'cyan', name: 'Cyan', hex: '#06b6d4' },
    { id: 'emerald', name: 'Emerald', hex: '#10b981' },
    { id: 'amber', name: 'Amber', hex: '#f59e0b' },
    { id: 'crimson', name: 'Crimson', hex: '#f43f5e' },
    { id: 'violet', name: 'Violet', hex: '#8b5cf6' },
    { id: 'sky', name: 'Sky Blue', hex: '#0ea5e9' },
  ];

  const fonts: { id: FontFamilyChoice; name: string; desc: string; sample: string }[] = [
    {
      id: 'mono',
      name: 'Modern Monospace',
      desc: 'JetBrains / Fira style - high clarity code & logs',
      sample: 'GET /api/v1/vuln HTTP/2',
    },
    {
      id: 'sans',
      name: 'Clean Modern Sans',
      desc: 'Balanced interface for extended auditor workflows',
      sample: 'OWASP Security Suite 2.4',
    },
    {
      id: 'retro',
      name: 'Retro Terminal (VT320)',
      desc: 'Classic vintage courier console feeling',
      sample: 'ROOT@SEC-OPS:~# audit',
    },
  ];

  const content = (
    <div
      id="visual-customizer-modal"
      className={`bg-slate-900 border border-slate-700/80 rounded-2xl w-full p-5 sm:p-6 shadow-2xl space-y-6 ${
        isModal ? 'max-w-3xl my-auto max-h-[90vh] overflow-y-auto' : 'max-w-5xl mx-auto'
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
            <Palette className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
              <span>Penyesuaian Visual &amp; Tema (Visual Customizer)</span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
                REAL-TIME
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Atur gaya warna, tipografi, kerapatan layar, efek retro scanlines, dan audio antarmuka sesuai preferensi Anda.
            </p>
          </div>
        </div>

        {isModal && onClose && (
          <button
            onClick={onClose}
            className="text-xs font-mono text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 transition"
          >
            [Tutup Esc]
          </button>
        )}
      </div>

        {/* Section 1: Preset Themes */}
        <div className="space-y-3">
          <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <Monitor className="w-3.5 h-3.5 text-cyan-400" />
            <span>1. Tema Warna Utama (Color Scheme)</span>
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
            {themePresets.map(preset => {
              const isSelected = settings.theme === preset.id;
              return (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => update({ theme: preset.id })}
                  className={`p-3 rounded-xl border text-left transition flex flex-col justify-between relative overflow-hidden group ${
                    isSelected
                      ? 'border-cyan-400 ring-2 ring-cyan-500/30 shadow-lg'
                      : 'border-slate-800 hover:border-slate-700 bg-slate-950/60'
                  }`}
                  style={{
                    backgroundColor: preset.isLight ? '#f1f5f9' : preset.bgHex,
                  }}
                >
                  <div className="flex items-center justify-between w-full mb-2">
                    <span
                      className={`text-xs font-bold ${
                        preset.isLight ? 'text-slate-900' : 'text-white'
                      }`}
                    >
                      {preset.name}
                    </span>
                    {isSelected && (
                      <span className="w-4 h-4 rounded-full bg-cyan-500 text-slate-950 flex items-center justify-center">
                        <Check className="w-3 h-3 stroke-[3]" />
                      </span>
                    )}
                  </div>

                  <p
                    className={`text-[11px] mb-2 leading-tight ${
                      preset.isLight ? 'text-slate-600' : 'text-slate-400'
                    }`}
                  >
                    {preset.tagline}
                  </p>

                  {/* Swatches preview */}
                  <div className="flex items-center gap-1.5 pt-1 border-t border-slate-700/30">
                    <span
                      className="w-3 h-3 rounded-full border border-black/20"
                      style={{ backgroundColor: preset.bgHex }}
                      title="Background"
                    />
                    <span
                      className="w-3 h-3 rounded-full border border-black/20"
                      style={{ backgroundColor: preset.accentHex }}
                      title="Accent"
                    />
                    <span
                      className="w-3 h-3 rounded-full border border-black/20"
                      style={{ backgroundColor: preset.borderHex }}
                      title="Border"
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Section 2: Accent Color & Typography */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2 border-t border-slate-800">
          {/* Accent Selection */}
          <div className="space-y-2.5">
            <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span>2. Warna Aksen Highlight</span>
            </label>

            <div className="grid grid-cols-3 gap-2">
              {accents.map(acc => (
                <button
                  key={acc.id}
                  type="button"
                  onClick={() => update({ accent: acc.id })}
                  className={`px-2.5 py-2 rounded-xl border flex items-center gap-2 text-xs transition ${
                    settings.accent === acc.id
                      ? 'border-white bg-slate-800 text-white font-semibold'
                      : 'border-slate-800 bg-slate-950/70 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <span
                    className="w-3 h-3 rounded-full shrink-0 shadow-sm"
                    style={{ backgroundColor: acc.hex }}
                  />
                  <span>{acc.name}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Typography */}
          <div className="space-y-2.5">
            <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Type className="w-3.5 h-3.5 text-cyan-400" />
              <span>3. Gaya Tipografi (Font Family)</span>
            </label>

            <div className="space-y-1.5">
              {fonts.map(font => (
                <button
                  key={font.id}
                  type="button"
                  onClick={() => update({ fontFamily: font.id })}
                  className={`w-full px-3 py-2 rounded-xl border text-left flex items-center justify-between transition ${
                    settings.fontFamily === font.id
                      ? 'border-cyan-500 bg-cyan-950/30 text-white'
                      : 'border-slate-800 bg-slate-950/60 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div>
                    <div className="text-xs font-semibold">{font.name}</div>
                    <div className="text-[10px] text-slate-400 font-mono">{font.sample}</div>
                  </div>
                  {settings.fontFamily === font.id && (
                    <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                  )}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Section 3: Density & Font Size Scale */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2 border-t border-slate-800">
          {/* UI Density */}
          <div className="space-y-2.5">
            <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-cyan-400" />
              <span>4. Kerapatan Layar (UI Density)</span>
            </label>

            <div className="grid grid-cols-3 gap-2">
              {(['compact', 'normal', 'spacious'] as UiDensity[]).map(d => (
                <button
                  key={d}
                  type="button"
                  onClick={() => update({ density: d })}
                  className={`py-2 px-2 rounded-xl border text-xs capitalize text-center transition ${
                    settings.density === d
                      ? 'bg-cyan-950 border-cyan-500 text-cyan-300 font-bold'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  {d === 'compact' ? 'Kompak' : d === 'normal' ? 'Standar' : 'Lega'}
                </button>
              ))}
            </div>
            <p className="text-[11px] text-slate-400 leading-tight">
              Mode kompak mengurangi ruang padding untuk melihat lebih banyak log audit dalam satu layar monitor.
            </p>
          </div>

          {/* Font Scaling */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Maximize2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>5. Skala Ukuran Teks</span>
              </label>
              <span className="text-xs font-mono font-bold text-cyan-400">
                {settings.fontSizeScale}%
              </span>
            </div>

            <div className="grid grid-cols-4 gap-2">
              {[90, 100, 110, 120].map(scale => (
                <button
                  key={scale}
                  type="button"
                  onClick={() => update({ fontSizeScale: scale })}
                  className={`py-2 rounded-xl border text-xs font-mono transition ${
                    settings.fontSizeScale === scale
                      ? 'bg-cyan-950 border-cyan-500 text-cyan-300 font-bold'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  {scale}%
                </button>
              ))}
            </div>
            <p className="text-[11px] text-slate-400 leading-tight">
              Gunakan 110% atau 120% untuk presentasi layar proyektor atau kenyamanan mata membaca laporan.
            </p>
          </div>
        </div>

        {/* Section 4: Retro CRT & Cyber Effects */}
        <div className="space-y-3 pt-2 border-t border-slate-800">
          <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
            <Tv className="w-3.5 h-3.5 text-cyan-400" />
            <span>6. Efek Visual &amp; Audio Khusus</span>
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {/* CRT Scanline Toggle */}
            <label className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3 cursor-pointer hover:border-slate-700 transition">
              <input
                type="checkbox"
                checked={settings.enableScanlines}
                onChange={e => update({ enableScanlines: e.target.checked })}
                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <div>
                <div className="text-xs font-bold text-slate-200">Retro CRT Scanlines</div>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Garis filter scanline ala monitor terminal tabung klasik.
                </p>
              </div>
            </label>

            {/* Neon Glow Toggle */}
            <label className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3 cursor-pointer hover:border-slate-700 transition">
              <input
                type="checkbox"
                checked={settings.enableNeonGlow}
                onChange={e => update({ enableNeonGlow: e.target.checked })}
                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <div>
                <div className="text-xs font-bold text-slate-200">Ambient Neon Glow</div>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Efek pendar neon pada border kartu dan status indikator.
                </p>
              </div>
            </label>

            {/* Background Grid Toggle */}
            <label className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-3 cursor-pointer hover:border-slate-700 transition">
              <input
                type="checkbox"
                checked={settings.enableBackgroundGrid}
                onChange={e => update({ enableBackgroundGrid: e.target.checked })}
                className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <div>
                <div className="text-xs font-bold text-slate-200">Dot Matrix Grid</div>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Pola titik matriks cyber di latar belakang kanvas.
                </p>
              </div>
            </label>

            {/* Cyber Sound FX Toggle */}
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between sm:col-span-2 md:col-span-3">
              <div className="flex items-center justify-between mb-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.enableSoundFx}
                    onChange={e => update({ enableSoundFx: e.target.checked })}
                    className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                    {settings.enableSoundFx ? (
                      <Volume2 className="w-3.5 h-3.5 text-cyan-400" />
                    ) : (
                      <VolumeX className="w-3.5 h-3.5 text-slate-500" />
                    )}
                    <span>Suara Audio Interaktif (Cyber Audio Clicks &amp; Scan Pings)</span>
                  </span>
                </label>

                {settings.enableSoundFx && (
                  <button
                    type="button"
                    onClick={handleTestSound}
                    className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 hover:bg-slate-700 border border-slate-700 transition"
                  >
                    Uji Suara Ping &rarr;
                  </button>
                )}
              </div>

              {settings.enableSoundFx && (
                <div className="flex items-center gap-3 pt-2 border-t border-slate-800">
                  <span className="text-[11px] text-slate-400">Volume:</span>
                  <input
                    type="range"
                    min="10"
                    max="100"
                    value={settings.soundVolume}
                    onChange={e => update({ soundVolume: Number(e.target.value) })}
                    className="w-full accent-cyan-500 h-1 bg-slate-800 rounded-lg"
                  />
                  <span className="text-[11px] font-mono text-cyan-400 w-8">
                    {settings.soundVolume}%
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Live Preview Card */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/70 space-y-2">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 flex items-center justify-between">
            <span>Live Interactive Preview</span>
            <span className="text-cyan-400 font-bold">
              Tema: {settings.theme} · Font: {settings.fontFamily}
            </span>
          </div>

          <div className="p-3 rounded-lg border border-slate-800 bg-slate-900 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <div>
                <div className="text-xs font-bold text-white">Target: api.internal.corp</div>
                <div className="text-[10px] text-slate-400 font-mono">
                  GET /v1/auth/token · Status 200 OK
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
                CRITICAL (CVSS 9.8)
              </span>
              <button
                type="button"
                className="px-3 py-1 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition"
              >
                Inspect Finding
              </button>
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800">
          <button
            type="button"
            onClick={onResetDefaults}
            className="px-3 py-2 rounded-xl text-xs text-slate-400 hover:text-white flex items-center gap-1.5 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Kembalikan ke Default</span>
          </button>

          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-950 transition flex items-center gap-1.5"
          >
            <Check className="w-4 h-4" />
            <span>Selesai &amp; Simpan Tampilan</span>
          </button>
        </div>
      </div>
  );

  if (isModal) {
    return (
      <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 overflow-y-auto">
        {content}
      </div>
    );
  }

  return content;
};

