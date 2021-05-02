---
title: "Translating R's poly() output to transform polynomial variable inputs for model prediction in .NET"
permalink: /post/translating-Rs-poly-output-to-transform-orthogonal-polynomial-variable-inputs-for-model-prediction-in-dotnet
layout: default
tags: dotnet R .net poly orthogonal-polynomial linear-regression machine-learning
---

When performing a linear regression in R and other stats platforms, polynomial variables are often transformed 'orthogonally', rather than raw. 

For example, when trying to find the optimal prediction model, consider the simplified model:  

<p><span> y = β<sub>0</sub> + β<sub>1</sub>x + β<sub>2</sub>x<sup>2</sup> + β<sub>3</sub>x<sup>3</sup> + ... + β<sub>n</sub>x<sup>n</sup> </span></p>

We are trying to find how much variance in Y is explained by each additional term n, and what the maximum number of terms should be. Transforming our fitting data x into orthogonal polynomials, using R's `poly()` function, allows the accurate estimation of each term's contribution.

For more explanation, see this stack exchange answer: [Why regression with orthogonal polynomials is useful](https://stats.stackexchange.com/a/433190/223569):

*"From the orthogonal polynomial model but not the raw polynomial model, we know that most of the variance explained in the outcome is due to the linear term, with very little coming from the square term and even less from the cubic term. The raw polynomial values don't tell that story."*

However when using linear regression as a maching learning tool, we want to make predictions on new data, and if we have a model fitted using orthogonal polynomials, we need to transform x using the same transformation that was used on the training data. We cannot use `poly()` on the new data as this will produce inconsistent results.

R's `poly()` transforms training data x into orthogonal polynomials, and the attributes alpha and norm2 can be used to transform the new data.

This transformation is covered in R [here](https://stackoverflow.com/a/26729318/3910619). C#, given its functional additions over the years, is also a good language to perform the transform, as the transformation requires creating different functions based on the polynomial order:

If we save R's `poly()` transformation parameters into JSON:

```R

z <- poly(1:10, 3)
orthogCoefs <- attributes(z)$coefs

orthogCoefsJson <- as.character(toJSON(orthogCoefs))

outputFile <- paste0("orthogCoefs.json")
write(x = orthogCoefsJson, file = outputFile, append = FALSE)

```

Then in C# our orthogonal transformation functions based on the transformation in our training data would look like this:

```csharp

public class PolyParameters
{
    public int Degree => Alpha.Count;

    public List<double> Alpha { get; set; }
    public List<double> Norm2 { get; set; }

    public Func<double, int, double> TransformationFunction { get; set; }
}


public static class PolyHelpers {

    public static PolyParameters ParsePolyParameters(string modelAdditionalParameters)
    {
        dynamic json = JObject.Parse(modelAdditionalParameters);
        return new PolyParameters
        {
            Alpha = json.temp.alpha.ToObject<List<double>>(),
            Norm2 = json.temp.norm2.ToObject<List<double>>()
        };
    }

    public static Func<double, int, double> GetPolyTransformation(PolyParameters polyParams)
    {
        var alphas = polyParams.Alpha;
        var norm2s = polyParams.Norm2;

        Func<double, double> F_0 = input => 1 / Math.Sqrt(norm2s[1]);

        Func<double, double> F_1 = input => (input - alphas[0]) / Math.Sqrt(norm2s[2]);
        var F = new List<Func<Double,Double>>
        {
            F_0,
            F_1
        };

        for (var i = 2; i <= polyParams.Degree; i++)
        {
            var index = i;
            Func<double,double> F_d = input => 
            (
                (input - alphas[index - 1]) *
                Math.Sqrt(norm2s[index]) * 
                F[index - 1](input) - norm2s[index] / Math.Sqrt(norm2s[index - 1]) * F[index - 2](input)
            ) / Math.Sqrt(norm2s[index + 1]);

            F.Add(F_d);
        }

        Func<double, int, double> transformationFunction = (input, degree) => F[degree](input);

        return transformationFunction;
    }

}

```

Then we'd use it like this: 

```csharp

public List<double> PolyTransformNewDataExample(List<double> fittedXCoeff, List<double> newXData)
{
  
  var orthogCoefsJson = File.ReadAllLines("orthogCoefs.json");
  
  var orthogCoefs = PolyHelpers.ParsePolyParameters(orthogCoefsJson);
  
  var orthogTransformationFunction = PolyHelpers.GetPolyTransformation(orthogCoefs);
  
  var newPredictions = new List<double>();
  foreach(var xVal in newXData) {
      
      double x0 = orthogTransformationFunction(1, 0)
      double x1 = orthogTransformationFunction(xVal, 1)
      double x2 = orthogTransformationFunction(xVal, 2)
      double x3 = orthogTransformationFunction(xVal, 3)
      
      double y = (fittedXCoeff[0] * x0) + (fittedXCoeff[1] * x1) + (fittedXCoeff[2] * x2) + (fittedXCoeff[3] * x3);
      
      newPredictions.Add(y);
  }
  
  return newPredictions;
  
}

```
