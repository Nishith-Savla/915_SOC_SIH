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
import logo from './nexot.png';


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
              noWrap
              sx={{ flexGrow: 1 }}
            >
          SOC - Team Avinya
            </Typography>
            
          </Toolbar>
        </AppBar>
      <Container component="main" maxWidth="xs" >
        <CssBaseline />
         <img src={logo} alt="Logo" style={{width:"25rem",marginTop:"5rem",marginRight:"9rem"}}/>
        <Box
          sx={{
            marginTop: 5,
            p:3,
            display: 'flex',
            borderRadius: '16px',
            border: 1,
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
          <Box component="form" noValidate sx={{ mt: 1 }}>
            <TextField
              margin="normal"
              required
              fullWidth
              id="email"
              value={email}
              
              onChange={(newValue) => {
              
              setEmail(newValue.target.value);
              
              }}
              label="Username"
              name="email"
              autoComplete="email"
              autoFocus
            />
            <TextField
              margin="normal"
              required
              fullWidth
              value={password}
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
