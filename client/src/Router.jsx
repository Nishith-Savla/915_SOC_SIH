import { BrowserRouter, Route, Routes } from "react-router-dom"
import App from './App'
import NotFound from './NotFound'
import SignIn from './SignIn'

const Router = () =>
{
    // const [options,setOptions] = React.useState(false)

    return(
        <div>
            <BrowserRouter> 
            <Routes>
                <Route path="/" element={<SignIn />}/>
                {/* <Route path="/start" element={<Start/>}/> */}

                <Route path="/dashboard" element={<App/>}/>

                <Route path="*" element={<NotFound/>}/>
                
            </Routes>
            </BrowserRouter>
        </div>
    )
}

export default Router
