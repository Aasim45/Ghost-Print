import React from 'react';
import { createRoot } from 'react-dom/client';
import { PatternWaves } from './components/ui/pattern-waves.jsx';

let mountedRoot = null;
let mountedElement = null;

window.mountPatternWaves = (element) => {
  if (!element) return;
  if (mountedElement !== element) {
    mountedRoot?.unmount();
    mountedRoot = createRoot(element);
    mountedElement = element;
  }

  mountedRoot.render(React.createElement(PatternWaves, {
    preset: 'silk',
    color: '#a18b98',
    backgroundColor: 'transparent',
    opacity: 0.24,
    speed: 0.18,
    fade: 'edges',
    interactive: true,
    cursorSize: 50,
    cursorStrength: 0.22,
    className: 'gg-pattern-waves-canvas',
    'aria-hidden': true,
  }));
};

window.unmountPatternWaves = () => {
  mountedRoot?.unmount();
  mountedRoot = null;
  mountedElement = null;
};
