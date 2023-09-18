import * as React from 'react';
import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import CssBaseline from '@mui/material/CssBaseline';
import TextField from '@mui/material/TextField';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';
// import LockIcon from '@mui/icons-material/Lock';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import {Link, useNavigate} from "react-router-dom";
import ParticleLinksBlue from './ParticleLinksBlue';
import { AppBar, Toolbar, IconButton, Badge } from '@mui/material';
import logo from './bluee.png';
import AccountCircle from '@mui/icons-material/AccountCircle';
import InputLabel from '@mui/material/InputLabel';
import InputAdornment from '@mui/material/InputAdornment';
import FormControl from '@mui/material/FormControl';
import { SmoothCorners } from 'react-smooth-corners'


const theme = createTheme();

export default function SignIn({innerRef,stateChanger, ...rest}: any) {

    const navigate = useNavigate();
    const [email, setEmail] = React.useState<string | Blob>("")
    const [password, setPassword] = React.useState<string | Blob>("")
    const handleSubmit = async () => {

    // console.log(resp.data)
    if(email=='user' && password=='12345')
    {

      // }
      // navigate("/start");
      navigate("/dashboard");

    }
    else{
      navigate("/");

    }
              
    
  };


  return (
    <div>
    <ParticleLinksBlue/> 
    <ThemeProvider theme={theme}>
    <CssBaseline />
        <AppBar position="absolute"  sx={{background: '#7607ba', height: '55px'}} >
          <Toolbar
            sx={{
              pr: '24px', // keep right padding when drawer closed
             
            }}
          >
            {/* <IconButton
              edge="start"
              color="inherit"
              aria-label="open drawer"
              onClick={toggleDrawer}
              sx={{
                marginRight: '36px',
                ...(open && { display: 'none' }),
              }}
            >
              <MenuIcon />
            </IconButton> */}
            <Typography
              component="h1"
              variant="h6"
              color="inherit"
              fontWeight={'bold'}
              noWrap
              sx={{ flexGrow: 1 }}
            >
          TEAM 915_SOC
            </Typography>
            
          </Toolbar>
        </AppBar>
      <Container component="main" maxWidth="xs" >
        <CssBaseline />
         <img src={logo} alt="Logo" style={{width:"140%",marginTop:"20%",marginRight:"20%", marginLeft:"-25%"}}/>
        <Box
          sx={{
            marginTop: 5,
            p:3,
            display: 'flex',
            borderRadius:'10px',
            border:1,
            
            backgroundColor: 'white',
            
            flexDirection: 'column',
            alignItems: 'center',
          }}
        >
          
          <Avatar sx={{ m: 1, bgcolor: 'secondary.main' }}>
            <LockOutlinedIcon />
            {/* <LockIcon/> */}
          </Avatar>
          <Typography component="h1" variant="h5">
            Sign in
          </Typography>
          <Box component="form" noValidate sx={{ mt: 1 }} >
          
            <TextField
              margin="normal"
              required
              fullWidth
              InputProps={{
                style: {
                  borderRadius: "15px",
                   
                  borderColor:"White",
                  borderStyle:"inherit"

                }
              }}


              id="email"
              
              
              sx={{ input:{color:'black'},borderRadius:"15px", background:'linear-gradient(90deg, #0cbff5, #6604cf)',opacity:"0.8" }}
              
              value={email}
              onChange={(newValue) => {
              setEmail(newValue.target.value);
              }}
              label="Username"
              label-font='Bold'
              name="email"
              autoComplete="email"
              autoFocus
            />
            
            <TextField
              margin="normal"
              required
              fullWidth
              InputProps={{
                style: {
                  borderRadius: "15px",
                }
              }}
              value={password}
              variant='outlined'
              
              sx={{ input: {color:'black',opacity:'100%'},borderRadius:"15px", background: 'linear-gradient(90deg, #0cbff5, #6604cf)',opacity:"0.8" }}
              onChange={(newValue) => {
              
                setPassword(newValue.target.value);
                
                }}
              name="password"
              label="Password"
              type="password"
              id="password"
              autoComplete="current-password"
            />
            
            <Button
              // type="submit"
              color='success'
              onClick={handleSubmit}
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
              
            >
              Sign In
            </Button>
            <Grid container>
              
              <Grid item>
                
                Don't have an account? Contact Admin
                
              </Grid>
            </Grid>
          </Box>
        </Box>

      </Container>
    </ThemeProvider>
    </div>
  );
}
