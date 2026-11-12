import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
// Fonts are bundled and served from this origin (the CSP allows fonts from 'self' only).
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./styles/index.css";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
