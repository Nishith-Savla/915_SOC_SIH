import * as React from 'react';
import Particles from "react-tsparticles";
import { loadFull } from "tsparticles";

const particlesInit = async (main) => {
    // you can initialize the tsParticles instance (main) here, adding custom shapes or presets
    // this loads the tsparticles package bundle, it's the easiest method for getting everything ready
    // starting from v2 you can add only the features you need reducing the bundle size
    await loadFull(main);
  };

export default function ParticleLinks() {

    // const [nodecolor, setnodecolor] = React.useState<string>(null);

    return(
        <Particles
        id="tsparticles"
        init={particlesInit}
        // loaded={particlesLoaded}
        options={
          {
            fpsLimit: 120,
            interactivity: {
              events: {
                onClick: {
                  enable: false,
                  mode: "push"
                },
                onHover: {
                  enable: true,
                  mode: "combine"
                },
                resize: true
              },
              modes: {
                push: {
                  quantity: 4
                },
                repulse: {
                  distance: 200,
                  duration: 0.4
                }
              }
            },
            particles: {
              color: {
                value: "#ffffff"
                // value: {nodecolor}

              },
              links: {
                // color: {LinkColor},
                color: "#ffffff",

                distance: 150,
                enable: true,
                opacity: 0.75,
                width: 2
              },
              collisions: {
                enable: false
              },
              move: {
                direction: "none",
                enable: true,
                random: true,
                bounce: false,
                speed: 1,
                straight: false
              },
              number: {
                density: {
                  enable: true,
                  area: 750
                },
                value: 80
              },
              opacity: {
                value: 0.75
              },
              shape: {
                type: "circle"
              },
              size: {
                value: { min: 1, max: 5 }
              }
            },
            detectRetina: true
          }
        }
      />
    );
}

