import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import AppContextProvider from './AppContext.jsx'
import './output.css'
// import './input.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <AppContextProvider >
      <App />
    </AppContextProvider>
  </StrictMode>,
)
